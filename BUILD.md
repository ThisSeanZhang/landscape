# Build and Development

This is the canonical local development guide for the repository.

## What to use

- Use `cargo build --workspace` and `cargo test --workspace` for normal Rust development.
- Use `./web.sh` for the frontend dev server.
- Use `pnpm` for direct frontend commands. If you do not have a global `pnpm`, use `corepack pnpm`.
- Use `bash ./build.sh -t <arch>` only for full integration or release-style builds.

Do not use `build.sh` for every edit. It rebuilds the frontend, regenerates API bindings, stages release static assets, and produces release artifacts.

## Requirements

- Linux kernel `6.9+`
- BTF/BPF enabled
- Node.js `22+`
- Rust toolchain

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

## Daily development

### Backend

```bash
cargo build --workspace
cargo test --workspace
```

### Frontend

```bash
./web.sh
```

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

`build.sh` installs frontend dependencies, exports OpenAPI through `./gen_ts_bindings.sh`, regenerates TypeScript bindings, builds the web UI, stages the Scalar static assets under `output/static`, and then builds the release backend binary.

## `sudo`

Do not use `sudo` for dependency installation, formatting, type generation, or normal frontend and Rust builds.

Use `sudo` only when running `landscape-webserver` on a real host, attaching eBPF programs, touching live interfaces, or validating real routing and packet-path behavior.

## Before opening a PR

```bash
cargo fmt --all
cargo test --workspace
pnpm --filter landscape-webui exec prettier --check "src/**/*.{vue,ts,js,json,css,scss}"
pnpm --filter landscape-webui build
```
