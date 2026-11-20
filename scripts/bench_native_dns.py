#!/usr/bin/env python3
"""Run repeatable, local-only native DNS pool benchmarks.

Examples:
  python3 scripts/bench_native_dns.py --quick --output /tmp/dns-smoke.jsonl
  python3 scripts/bench_native_dns.py --concurrency 1,8,32,128 --repeats 5
  python3 scripts/bench_native_dns.py --cases normal --concurrency 1,32

Builds an optimized bench binary once, then starts a fresh process for each run.
Use CARGO_PROFILE_BENCH_LTO=off CARGO_PROFILE_BENCH_CODEGEN_UNITS=16 for a faster
build; these overrides are recorded and MUST match between compared revisions.
No public DNS, privileged network configuration, or complete Landscape service
is used. CAP_NET_ADMIN may be required by the native socket provider.

The pool defaults to one pinned CPU and one worker; --pool-cpus 0,6 enables two. Upstream threads inherit a separate
CPU set; --upstream-cpus 2,4 --upstream-workers 2 enables multiple upstream cores.
The runner rejects shared physical cores (including SMT siblings).
This is closed-loop load. The responder shares the process, and may itself bottleneck. Results are NOT production DNS
capacity numbers. Fault warmup is disabled; normal warmup uses 500 queries.
Each run includes a serial phase followed by the selected concurrency.
Errors are valid outcomes (not useful throughput); responder overflow is fatal.
The first-UDP-loss workload uses unique names and may recover through TCP.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "normal": ("normal", 1, 1),
    "select2": ("normal", 2, 1),
    "fanout2": ("normal", 2, 2),
    "rank4": ("normal", 4, 2),
    "fanout4": ("normal", 4, 4),
    "slow": ("slow_first", 2, 2),
    "loss": ("drop_first_udp", 1, 1),
    "blackhole": ("blackhole_first", 2, 2),
    "servfail": ("servfail_first", 1, 1),
}


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--quick", action="store_true", help="0.2s serial / 0.5s concurrent, one repetition; smoke test only")
    parser.add_argument("--cases", default=",".join(CASES), help="comma-separated: " + ",".join(CASES))
    parser.add_argument("--concurrency", default="1,32", help="comma-separated positive worker counts")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seconds", type=float, default=10, help="concurrent phase duration")
    parser.add_argument("--serial-seconds", type=float, default=2)
    pool_group = parser.add_mutually_exclusive_group()
    pool_group.add_argument("--pool-cpu", type=int, help="single pool CPU; defaults to first allowed CPU")
    pool_group.add_argument("--pool-cpus", help="comma-separated pool CPUs")
    parser.add_argument("--pool-workers", type=int, help="pool workers; defaults to number of pool CPUs")
    parser.add_argument("--upstream-cpus", help="comma-separated CPUs, on different physical cores from pool; default: one separate core")
    parser.add_argument("--upstream-workers", type=int, help="upstream workers; defaults to number of upstream CPUs")
    parser.add_argument("--output", type=Path, default=Path("/tmp/landscape-native-dns-bench.jsonl"))
    parser.add_argument("--binary", type=Path, help="reuse a binary; caller must ensure it matches the intended sources/profile")
    args = parser.parse_args()
    try:
        cases = args.cases.split(",")
        concurrency = [int(n) for n in args.concurrency.split(",")]
        if not all(c in CASES for c in cases) or min(concurrency) < 1:
            raise ValueError()
        if args.repeats < 1 or not (0 < args.seconds < 86400) or not (0 < args.serial_seconds < 86400):
            raise ValueError()
    except ValueError:
        parser.error("invalid case, concurrency, duration or repeat count")
    allowed = sorted(os.sched_getaffinity(0))
    def physical_core(cpu):
        topology = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
        return ((topology / "physical_package_id").read_text().strip(),
                (topology / "core_id").read_text().strip())
    try:
        pool_cpus = sorted(set(int(c) for c in args.pool_cpus.split(","))) if args.pool_cpus else [allowed[0] if args.pool_cpu is None else args.pool_cpu]
        if any(c not in allowed for c in pool_cpus):
            parser.error("pool CPU is outside allowed affinity")
        pool_cores = {physical_core(c) for c in pool_cpus}
        if len(pool_cores) != len(pool_cpus):
            parser.error("pool CPUs must be on distinct physical cores")
        if args.upstream_cpus:
            upstream_cpus = sorted(set(int(c) for c in args.upstream_cpus.split(",")))
        else:
            upstream_cpus = [next(c for c in allowed if physical_core(c) not in pool_cores)]
        if any(c not in allowed for c in upstream_cpus):
            parser.error("upstream CPU is outside allowed affinity")
        if any(physical_core(c) in pool_cores for c in upstream_cpus):
            parser.error("upstream must not share the pool CPU or its SMT sibling")
    except (OSError, ValueError, StopIteration):
        parser.error("cannot select separate physical cores from the available CPU topology")
    pool_workers = args.pool_workers if args.pool_workers is not None else len(pool_cpus)
    upstream_workers = args.upstream_workers if args.upstream_workers is not None else len(upstream_cpus)
    if upstream_workers < 1 or pool_workers < 1:
        parser.error("worker counts must be positive")
    print(f"Pool: CPUs {pool_cpus}, {pool_workers} worker(s); upstream: CPUs {upstream_cpus}, {upstream_workers} worker(s)", flush=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("LANDSCAPE_BENCH_")}
    if args.binary:
        binary = args.binary.resolve()
    else:
        build = subprocess.run([
            "cargo", "build", "--locked", "-p", "landscape-dns", "--features", "bench",
            "--bench", "native_upstream", "--profile", "bench", "--message-format=json-render-diagnostics",
        ], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, check=True)
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
        binaries = [a["executable"] for a in artifacts if a.get("reason") == "compiler-artifact"
                    and a.get("target", {}).get("name") == "native_upstream" and a.get("executable")]
        if not binaries:
            raise RuntimeError("Cargo did not return the benchmark executable")
        binary = Path(binaries[-1])
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    metadata = {
        "kind": "metadata", "commit": command("git", "rev-parse", "HEAD"),
        "worktree_status": command("git", "status", "--short"),
        "tracked_diff_sha256": hashlib.sha256(subprocess.check_output(["git", "diff", "HEAD"], cwd=ROOT)).hexdigest(),
        "rustc": command("rustc", "-Vv"), "platform": platform.platform(),
        "cpu_count": os.cpu_count(), "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "binary": str(binary), "binary_sha256": binary_hash, "reused_binary": bool(args.binary),
        "build_environment": {k: v for k, v in env.items() if k.startswith("CARGO_PROFILE_") or k in ("RUSTFLAGS", "CLANG", "RUSTUP_TOOLCHAIN")},
        "runtime_threads": pool_workers, "pool_cpus": pool_cpus, "upstream_cpus": upstream_cpus,
        "upstream_workers": upstream_workers,
        "cpu_topology": {str(c): physical_core(c) for c in [*pool_cpus, *upstream_cpus]}, "started_at_unix": time.time(),
        "quick": args.quick,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation avoids silently overwriting an earlier baseline.
    with args.output.open("x") as output:
        output.write(json.dumps(metadata) + "\n")
        for repeat in range(1 if args.quick else args.repeats):
            for case in cases:
                scenario, endpoints, fanout = CASES[case]
                for workers in concurrency:
                    run_env = env | {
                        "TOKIO_WORKER_THREADS": str(pool_workers),
                        "LANDSCAPE_BENCH_POOL_CPUS": ",".join(map(str, pool_cpus)),
                        "LANDSCAPE_BENCH_POOL_WORKERS": str(pool_workers),
                        "LANDSCAPE_BENCH_UPSTREAM_CPUS": ",".join(map(str, upstream_cpus)),
                        "LANDSCAPE_BENCH_UPSTREAM_WORKERS": str(upstream_workers),
                        "LANDSCAPE_BENCH_SCENARIO": scenario,
                        "LANDSCAPE_BENCH_ENDPOINTS": str(endpoints),
                        "LANDSCAPE_BENCH_FANOUT": str(fanout),
                        "LANDSCAPE_BENCH_CONCURRENCY": str(workers),
                        "LANDSCAPE_BENCH_SEQ_SECS": "0.2" if args.quick else str(args.serial_seconds),
                        "LANDSCAPE_BENCH_CONC_SECS": "0.5" if args.quick else str(args.seconds),
                        "LANDSCAPE_BENCH_WARMUP": "50" if args.quick and scenario == "normal" else "500" if scenario == "normal" else "0",
                    }
                    report = json.loads(subprocess.check_output([str(binary)], cwd=ROOT, env=run_env, text=True))
                    if report["pool_affinity"] != pool_cpus or report["upstream_affinity"] != upstream_cpus:
                        raise RuntimeError("benchmark affinity does not match requested layout")
                    result = {"kind": "result", "case": case, "repeat": repeat + 1, "concurrency": workers, "report": report}
                    output.write(json.dumps(result) + "\n")
                    output.flush()
                    phase = report["concurrent"]
                    print(f"{case:10s} c={workers:3d} run={repeat+1} success_qps={phase['success_qps']:.0f} "
                          f"errors={phase['error_rate']:.2%} p99={phase['success_latency']['p99_us']}us "
                          f"upstream/query={phase['upstream_requests_per_query']:.2f}", flush=True)
                    if any(t["responder_overflows"] for p in (report["sequential"], phase) for t in p["upstream"]):
                        raise RuntimeError("responder capacity exceeded; this measurement is invalid")
    print(f"Results: {args.output}")


if __name__ == "__main__":
    main()
