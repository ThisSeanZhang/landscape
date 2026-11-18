# Build and Development

This is the canonical local development guide for the repository.

## What to use

Run `just --list` in the repository to see available tasks. On Debian 13, install the runner with `sudo apt install just`.

- Run `just init` for initial setup. Use `just build` and `just test` for daily backend development and `./web.sh` for the frontend dev server.
- Use `just fmt` for formatting, with options such as `--rust`. Run the relevant Containerlab cases, for example `just e2e-gateway` for Gateway changes. [E2E test selection](tests/e2e/containerlab/README.md#按改动范围选择用例)
- Use `./build.sh -t <arch>` for full integration or release builds. It rebuilds the frontend, stages static assets, and builds the backend.

## Requirements

- Linux kernel `6.12+`
- BTF/BPF enabled
- Node.js `22+`
- Rust toolchain (pinned to `1.98.0` via [`rust-toolchain.toml`](./rust-toolchain.toml))
- Clang/LLVM `19+` for the eBPF arena backend. Clang 18 and older compile the
  BPF sources but do not emit `BPF_ADDR_SPACE_CAST`, so the kernel verifier
  rejects the resulting programs with `Permission denied`.

Install the system packages (Debian 13):

```bash
sudo apt-get update
sudo apt-get install -y cmake clang-19 clang-format-19 lld-19 llvm-19 libclang-19-dev \
  gcc g++ make pkg-config libelf-dev libzstd-dev zlib1g-dev
export CLANG=clang-19
```

## pnpm and Corepack

This repository pins `pnpm` in [`package.json`](./package.json). If you do not have a global `pnpm`, enable Corepack:

```bash
corepack enable
corepack pnpm --version
```

Repository scripts such as `./web.sh`, `./gen_ts_bindings.sh`, and `bash ./build.sh` resolve `pnpm` through `scripts/pnpm_cmd.sh`, preferring `corepack pnpm` when available. See <https://pnpm.io/installation#using-corepack>.

## Initial setup

Install workspace dependencies and generate the TypeScript client:

```bash
just init
```

To install dependencies separately, run `just pnpm install --frozen-lockfile`.

Run `just bindings` again whenever backend OpenAPI routes or schemas change. `build.sh` and `./web.sh` call it with `--if-stale`, which skips regeneration only when `landscape-types/openapi.json`, `landscape-types/src/api/schemas/index.ts`, and `landscape-types/.bindings.lock` all exist.

## Daily development

### Backend

```bash
just build
just test        # unit tests
just test-bpf    # eBPF integration tests (root required)
```

`cargo tt` and `cargo ttb` are the Cargo aliases for the two test tasks above. BPF skeletons are compiled in parallel and cached by content hash; set `BPF_BUILD_JOBS` to cap clang parallelism on memory-constrained machines.

### Frontend

```bash
./web.sh
```

`./web.sh` performs the same lock-based API bindings check before starting `landscape-webui` in dev mode.

To start the frontend directly with existing bindings:

```bash
just pnpm --filter landscape-webui dev
```

If the UI build fails with missing `@landscape-router/types/...` modules, regenerate `openapi.json` and `landscape-types`.

`just web` builds the app bundle itself. Release-style static packaging, including the Scalar assets served by the backend, is handled by `./build.sh -t <arch>`.

## Full build

Use this for local verification builds:

```bash
./build.sh -t x86_64
```

`build.sh` installs frontend dependencies, regenerates API bindings only when the generated files or lock file are missing, builds the web UI, stages the Scalar static assets under `output/static`, and then builds the backend binary. It uses the `fast` Cargo profile by default (no size optimizations, fastest compile). For release-style artifacts, use:

```bash
./build.sh -t x86_64 --release
```

## `sudo`

Do not use `sudo` for pnpm dependency installation, formatting, type generation, or normal frontend and Rust builds.

Use `sudo` only when running `landscape-webserver` on a real host, attaching eBPF programs, touching live interfaces, or validating real routing and packet-path behavior.

## Before opening a PR

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the formatting and test checklist.
