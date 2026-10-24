use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{available_parallelism, scope};

use libbpf_cargo::SkeletonBuilder;

/// Bump to invalidate every skeleton cache entry after changing generation logic.
const SKELETON_GEN_VERSION: u64 = 3;

/// BPF arena pointer accesses require `addr_space_cast`, which LLVM only
/// emits correctly starting with Clang 19. Clang 18 and older compile the
/// code successfully but produce a verifier-rejected program.
const MIN_CLANG_MAJOR: u32 = 19;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn clang_binary() -> OsString {
    env::var_os("CLANG").unwrap_or_else(|| OsString::from("clang"))
}

fn check_clang(clang: &OsStr) -> Vec<u8> {
    let output = Command::new(clang).arg("--version").output().unwrap_or_else(|e| {
        panic!(
            "failed to execute `{}`: {e}. Install Clang {MIN_CLANG_MAJOR}+ and set CLANG \
             to its path if necessary",
            Path::new(clang).display()
        )
    });
    assert!(
        output.status.success(),
        "`{} --version` failed with status {}",
        Path::new(clang).display(),
        output.status
    );

    let version = String::from_utf8_lossy(&output.stdout);
    let first_line = version.lines().next().unwrap_or("<empty>");
    let major = first_line
        .split_whitespace()
        .find_map(|word| {
            let word = word.trim_start_matches('v');
            let mut parts = word.split('.');
            let major = parts.next()?.parse::<u32>().ok()?;
            // Require at least major.minor so unrelated numeric tokens do
            // not get mistaken for the compiler version.
            parts.next()?;
            Some(major)
        })
        .unwrap_or_else(|| panic!("failed to parse Clang version from: {first_line}"));

    assert!(
        major >= MIN_CLANG_MAJOR,
        "landscape-ebpf requires Clang {MIN_CLANG_MAJOR}+, found: {first_line}. \
         Clang 19+ is required to emit BPF arena `addr_space_cast` instructions. \
         Install clang-19 and set CLANG to its path."
    );

    println!("cargo:warning=BPF compiler: {first_line}");
    output.stdout
}

fn emit_rerun_if_changed(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());

    if !path.is_dir() {
        return;
    }

    for entry in fs::read_dir(path).expect("Failed to read bpf source directory") {
        let path = entry.expect("Failed to read bpf source entry").path();
        emit_rerun_if_changed(&path);
    }
}

struct BpfJob {
    source: PathBuf,
    skel: PathBuf,
    hash: PathBuf,
}

fn collect_bpf_in_dir(dir: &Path, project_root: &Path, jobs: &mut Vec<BpfJob>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| {
        panic!("Failed to read directory: {}: {}", dir.display(), e);
    }) {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(e) => {
                eprintln!("Error reading directory entry: {}", e);
                continue;
            }
        };

        if path.is_dir() {
            continue;
        }

        let file_name = path.file_name().and_then(|name| name.to_str());
        let Some(file_name) = file_name else {
            eprintln!("Invalid file name: {:?}", path);
            continue;
        };

        if !file_name.ends_with(".bpf.c") {
            continue;
        }

        let file_stem = file_name.trim_end_matches(".bpf.c").to_string();
        jobs.push(BpfJob {
            source: path,
            skel: project_root.join(format!("{file_stem}.skel.rs")),
            hash: project_root.join(format!("{file_stem}.skel.hash")),
        });
    }
}

/// Collect the `bpf-test`-only BPF trees: correctness-test programs under
/// `src/bpf/tests/` and benchmarks under `src/bpf/bench/`. `.bpf.c` files may
/// sit at either level of those trees.
fn collect_aux_bpf(dir: &Path, project_root: &Path, jobs: &mut Vec<BpfJob>) {
    if !dir.is_dir() {
        return;
    }
    collect_bpf_in_dir(dir, project_root, jobs);
    for entry in fs::read_dir(dir).unwrap_or_else(|e| {
        panic!("Failed to read BPF directory: {}: {}", dir.display(), e);
    }) {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(e) => {
                eprintln!("Error reading test directory entry: {}", e);
                continue;
            }
        };
        if path.is_dir() {
            collect_bpf_in_dir(&path, project_root, jobs);
        }
    }
}

/// Length-prefixed byte buffer folded into one FNV-1a digest; length prefixes
/// keep adjacent fields from colliding.
struct KeyBuilder(Vec<u8>);

impl KeyBuilder {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn field(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        self.0.extend_from_slice(bytes);
    }

    fn finish(&self) -> u64 {
        let mut h = FNV_OFFSET;
        for &b in &self.0 {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }
}

fn hash_file_into(path: &Path, key: &mut KeyBuilder) {
    key.field(path.to_string_lossy().as_bytes());
    match fs::read(path) {
        Ok(bytes) => key.field(&bytes),
        Err(_) => key.field(b"<unreadable>"),
    }
}

/// Hash every header under `dir` (recursively, in a stable order) so that
/// editing a shared `.h` invalidates the skeletons that include it.
fn hash_headers(dir: &Path, key: &mut KeyBuilder) {
    let mut headers = Vec::new();
    collect_files_with_extension(dir, "h", &mut headers);
    headers.sort();
    for header in headers {
        hash_file_into(&header, key);
    }
}

fn collect_files_with_extension(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files_with_extension(&path, ext, out);
        } else if path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
}

/// Only the lock entries that can change skeleton generation output; a full
/// Cargo.lock hash would needlessly flush the cache on unrelated dep bumps.
fn lock_packages_fingerprint(lock_path: &Path) -> Vec<u8> {
    let watched = ["libbpf-cargo", "libbpf-sys", "vmlinux"];
    let mut out = Vec::new();
    let Ok(text) = fs::read_to_string(lock_path) else {
        return out;
    };
    for block in text.split("[[package]]").skip(1) {
        if watched.iter().any(|name| block.contains(&format!("name = \"{name}\""))) {
            out.extend_from_slice(block.as_bytes());
        }
    }
    out
}

/// Everything that affects all skeletons: generator version, arch, clang args,
/// vmlinux headers, shared BPF headers, clang binary, and libbpf toolchain.
fn environment_key(
    target_arch: &str,
    clang_args: &[&OsStr],
    vmlinux_path: &Path,
    clang_version: &[u8],
) -> u64 {
    let mut key = KeyBuilder::new();
    key.field(&SKELETON_GEN_VERSION.to_le_bytes());
    key.field(target_arch.as_bytes());
    for arg in clang_args {
        key.field(arg.as_encoded_bytes());
    }

    let mut vmlinux_files = Vec::new();
    collect_files_with_extension(vmlinux_path, "h", &mut vmlinux_files);
    vmlinux_files.sort();
    for header in &vmlinux_files {
        hash_file_into(header, &mut key);
    }
    hash_headers(Path::new("src/bpf"), &mut key);

    key.field(clang_version);

    if let Some(manifest_dir) = env::var_os("CARGO_MANIFEST_DIR") {
        let lock = Path::new(&manifest_dir).join("../Cargo.lock");
        key.field(&lock_packages_fingerprint(&lock));
    }

    key.finish()
}

fn job_key(job: &BpfJob, env_key: u64) -> u64 {
    let mut key = KeyBuilder::new();
    key.field(&env_key.to_le_bytes());
    match fs::read(&job.source) {
        Ok(bytes) => key.field(&bytes),
        Err(_) => key.field(b"<unreadable>"),
    }
    key.finish()
}

/// Worker pool size: honor `BPF_BUILD_JOBS`, otherwise the CPUs available to
/// this process (respects cgroup quotas / affinity), capped for sanity.
fn worker_count() -> usize {
    if let Ok(value) = env::var("BPF_BUILD_JOBS")
        && let Ok(n) = value.trim().parse::<usize>()
        && n > 0
    {
        return n;
    }
    available_parallelism().map(|n| n.get()).unwrap_or(1).min(32)
}

/// Build one skeleton unless the cached hash says generation inputs are
/// unchanged. Returns `true` when clang actually ran.
fn build_one(job: &BpfJob, key: u64, clang_args: &[&OsStr], clang: &OsStr) -> Result<bool, String> {
    let key_str = format!("{key:016x}");
    if job.skel.exists() && fs::read_to_string(&job.hash).is_ok_and(|h| h.trim() == key_str) {
        return Ok(false);
    }

    println!("Building BPF skeleton: {}", job.source.display());
    SkeletonBuilder::new()
        .source(&job.source)
        .clang(clang)
        .clang_args(clang_args)
        .build_and_generate(&job.skel)
        .map_err(|e| format!("{}: {:?}", job.source.display(), e))?;
    fs::write(&job.hash, &key_str).map_err(|e| format!("{}: {e}", job.hash.display()))?;
    Ok(true)
}

fn run_jobs(jobs: &[(BpfJob, u64)], clang_args: &[&OsStr], clang: &OsStr) {
    if jobs.is_empty() {
        return;
    }

    let next = AtomicUsize::new(0);
    let built = AtomicUsize::new(0);
    let cached = AtomicUsize::new(0);
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());

    let worker = || loop {
        let i = next.fetch_add(1, Ordering::Relaxed);
        let Some((job, key)) = jobs.get(i) else {
            break;
        };
        match build_one(job, *key, clang_args, clang) {
            Ok(true) => {
                built.fetch_add(1, Ordering::Relaxed);
            }
            Ok(false) => {
                cached.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => errors.lock().unwrap().push(e),
        }
    };

    let workers = worker_count().min(jobs.len());
    if workers <= 1 {
        worker();
    } else {
        scope(|s| {
            for _ in 0..workers {
                #[allow(clippy::redundant_closure)]
                s.spawn(|| worker());
            }
        });
    }

    println!(
        "BPF skeletons: {} built, {} cached ({} worker(s))",
        built.load(Ordering::Relaxed),
        cached.load(Ordering::Relaxed),
        workers
    );

    let errors = errors.into_inner().unwrap();
    if !errors.is_empty() {
        panic!("BPF skeleton build failed for {} source(s):\n{}", errors.len(), errors.join("\n"));
    }
}

/// Main function of the build script.
fn main() {
    let project_root = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf_rs");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    println!("build target arch is: {}", target_arch);

    println!("cargo:rerun-if-env-changed=CLANG");
    let clang = clang_binary();
    let clang_version = check_clang(&clang);

    emit_rerun_if_changed(Path::new("src/bpf"));

    let vmlinux_path = vmlinux::include_path_root().join(&target_arch);
    let mut clang_args: Vec<&OsStr> = vec![
        OsStr::new("-Wall"),
        OsStr::new("-Wno-compare-distinct-pointer-types"),
        OsStr::new("-I"),
        vmlinux_path.as_os_str(),
        OsStr::new("-I"),
        OsStr::new("src/bpf"),
        OsStr::new("-mcpu=v2"),
    ];

    if target_arch.contains("riscv") {
        clang_args.push(OsStr::new("-DLAND_ARCH_RISCV"));
    }

    /// Test/bench feature -> BPF source directories (relative to crate root).
    /// `test-nat` also pulls `chain/` because the NAT session tests reuse the
    /// chain helpers' `test_xdp_dummy` program. Directories may be requested
    /// by several features; jobs are deduplicated below.
    const FEATURE_TEST_DIRS: &[(&str, &[&str])] = &[
        ("test-route", &["src/bpf/tests/route"]),
        ("test-nat", &["src/bpf/tests/nat", "src/bpf/tests/chain"]),
        ("test-scanner", &["src/bpf/tests/scanner"]),
        ("test-reader", &["src/bpf/tests/reader"]),
        ("test-chain", &["src/bpf/tests/chain"]),
        ("test-metric", &["src/bpf/tests/metric"]),
        ("test-misc", &["src/bpf/tests/misc"]),
        ("bench", &["src/bpf/bench"]),
    ];

    let mut jobs = Vec::new();
    collect_bpf_in_dir(Path::new("src/bpf/"), &project_root, &mut jobs);
    for (feature, dirs) in FEATURE_TEST_DIRS {
        let env_var = format!("CARGO_FEATURE_{}", feature.to_uppercase().replace('-', "_"));
        if env::var_os(&env_var).is_some() {
            for dir in *dirs {
                collect_aux_bpf(Path::new(dir), &project_root, &mut jobs);
            }
        }
    }
    // A feature set can request the same directory twice (e.g. test-nat +
    // test-chain both pull src/bpf/tests/chain); keep one job per source.
    jobs.sort_by(|a, b| a.source.cmp(&b.source));
    jobs.dedup_by(|a, b| a.source == b.source);

    let env_key = environment_key(&target_arch, &clang_args, &vmlinux_path, &clang_version);
    let keyed: Vec<(BpfJob, u64)> = jobs
        .into_iter()
        .map(|job| {
            let key = job_key(&job, env_key);
            (job, key)
        })
        .collect();
    run_jobs(&keyed, &clang_args, &clang);
}
