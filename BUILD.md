# Build and Development

This is the canonical local development guide for the repository.

## What to use

- Use `cargo build --workspace` and `cargo test --workspace` for normal Rust development.
- Use `cargo test -p landscape-ebpf --features bpf-test` for the eBPF integration tests (requires root).
- Use `./web.sh` for the frontend dev server.
- Use `pnpm` for direct frontend commands. If you do not have a global `pnpm`, use `corepack pnpm`.
- Use `bash ./build.sh -t <arch>` only for full integration or release-style builds.

Do not use `build.sh` for every edit. It rebuilds the frontend, ensures API bindings exist when needed, stages release static assets, and produces release artifacts.

## Requirements

- Linux kernel `6.12+`
- BTF/BPF enabled
- Node.js `22+`
- Rust toolchain (pinned to `1.98.0` via [`rust-toolchain.toml`](./rust-toolchain.toml))

Install the system packages used by CI:

```bash
sudo apt-get update
sudo apt-get install -y cmake clang gcc make pkg-config libelf-dev libclang-dev zlib1g-dev
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
pnpm install --frozen-lockfile
./gen_ts_bindings.sh
```

If you use Corepack, replace `pnpm` with `corepack pnpm`.

Run `./gen_ts_bindings.sh` again whenever backend OpenAPI routes or schemas change. `build.sh` and `./web.sh` call it with `--if-stale`, which skips regeneration only when `landscape-types/openapi.json`, `landscape-types/src/api/schemas/index.ts`, and `landscape-types/.bindings.lock` all exist.

## Daily development

### Backend

```bash
cargo build --workspace
cargo test --workspace                              # unit tests
cargo test -p landscape-ebpf --features bpf-test    # eBPF integration tests (root required)
```

`cargo tt` and `cargo ttb` are aliases for the two test commands above. BPF skeletons are compiled in parallel and cached by content hash; set `BPF_BUILD_JOBS` to cap clang parallelism on memory-constrained machines.

### Frontend

```bash
./web.sh
```

`./web.sh` performs the same lock-based API bindings check before starting `landscape-webui` in dev mode.

Equivalent direct command:

```bash
pnpm --filter landscape-webui dev
```

If the UI build fails with missing `@landscape-router/types/...` modules, regenerate `openapi.json` and `landscape-types`.

`pnpm --filter landscape-webui build` builds the app bundle itself. Release-style static packaging, including the Scalar assets served by the backend, is handled by `bash ./build.sh -t <arch>`.

## Full build

Use this when you want the same general flow as CI:

```bash
bash ./build.sh -t x86_64
```

`build.sh` installs frontend dependencies, regenerates API bindings only when the generated files or lock file are missing, builds the web UI, stages the Scalar static assets under `output/static`, and then builds the release backend binary.

## `sudo`

Do not use `sudo` for dependency installation, formatting, type generation, or normal frontend and Rust builds.

Use `sudo` only when running `landscape-webserver` on a real host, attaching eBPF programs, touching live interfaces, or validating real routing and packet-path behavior.

## Before opening a PR

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the formatting and test checklist.
