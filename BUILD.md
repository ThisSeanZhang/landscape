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

- Linux kernel `6.9+`
- BTF/BPF enabled
- Node.js `22+`
- Rust toolchain (pinned to `1.98.0` via [`rust-toolchain.toml`](./rust-toolchain.toml))

Install the system packages used by CI:

```bash
sudo apt-get update
sudo apt-get install -y cmake clang curl gcc llvm make pkg-config libelf-dev libclang-dev zlib1g-dev zstd
```

## pnpm and Corepack

This repository pins `pnpm` in [`package.json`](./package.json).

If you already have `pnpm` installed globally, use it directly:

```bash
pnpm --version
```

If you do not want a global `pnpm`, use Corepack instead:

```bash
corepack enable
corepack pnpm --version
```

If you want the `pnpm` command itself to be available through Corepack, run:

```bash
corepack enable pnpm
```

Repository wrapper scripts such as `./web.sh`, `./gen_ts_bindings.sh`, and `bash ./build.sh` already resolve `pnpm` through `scripts/pnpm_cmd.sh`. When Corepack is available and usable, they prefer `corepack pnpm`; otherwise they fall back to a global `pnpm`.

Reference: <https://pnpm.io/installation#using-corepack>

## Initial setup

Install workspace dependencies:

```bash
pnpm install --frozen-lockfile
```

If you are using Corepack instead of a global `pnpm`, replace `pnpm` with `corepack pnpm`.

The frontend imports generated code from `landscape-types`, so generate it before frontend work:

```bash
./gen_ts_bindings.sh
```

`./gen_ts_bindings.sh` exports `openapi.json` and regenerates the TypeScript client. Run it again whenever you change backend OpenAPI routes or schemas.

Directly running `./gen_ts_bindings.sh` always forces a fresh export and regeneration.

`bash ./build.sh -t <arch>` is different: it calls `./gen_ts_bindings.sh --if-stale` internally so repeated full builds do not regenerate bindings once the generated files and lock file already exist.

`./web.sh` also calls `./gen_ts_bindings.sh --if-stale` before starting the frontend dev server, so frontend development avoids paying the regeneration cost on every run.

If you explicitly want the same lock-based skip behavior outside the full build flow, use:

```bash
./gen_ts_bindings.sh --if-stale
```

This skips regeneration only when `landscape-types/openapi.json`, `landscape-types/src/api/schemas/index.ts`, and `landscape-types/.bindings.lock` all exist.

## Daily development

### Backend

```bash
cargo build --workspace
cargo test --workspace                              # unit tests
cargo test -p landscape-ebpf --features bpf-test    # eBPF integration tests (root required)
```

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

```bash
cargo fmt --all
cargo test --workspace
cargo test -p landscape-ebpf --features bpf-test
pnpm --filter landscape-webui exec prettier --check "src/**/*.{vue,ts,js,json,css,scss}"
pnpm --filter landscape-webui build
```
