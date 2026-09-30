# 构建与本地开发

本文件用于说明仓库的本地开发流程。如与 [BUILD.md](./BUILD.md) 不一致，以英文版为准。

## 该用什么命令

- 日常 Rust 开发使用 `cargo build --workspace` 和 `cargo test --workspace`
- eBPF 集成测试使用 `cargo test -p landscape-ebpf --features bpf-test`（需要 root）
- 前端开发优先使用 `./web.sh`
- 前端命令使用 `pnpm`。如果你没有全局安装 `pnpm`，再使用 `corepack pnpm`
- 只有在整仓联调或发布式构建时才使用 `bash ./build.sh -t <arch>`

不要把 `build.sh` 当作日常开发入口。它会重建前端、按需确保 API 类型产物存在、整理 release 用静态资源，并产出 release 级别的构建结果。

## 环境要求

- Linux 内核 `6.9+`
- 启用 BTF/BPF
- Node.js `22+`
- Rust 工具链（通过 [`rust-toolchain.toml`](./rust-toolchain.toml) 固定为 `1.98.0`）

系统依赖按 CI 安装：

```bash
sudo apt-get update
sudo apt-get install -y cmake clang curl gcc llvm make pkg-config libelf-dev libclang-dev zlib1g-dev zstd
```

## pnpm 与 Corepack

仓库在 [`package.json`](./package.json) 里锁定了 `pnpm` 版本。

如果你已经全局安装了 `pnpm`，直接使用：

```bash
pnpm --version
```

如果你不想全局安装 `pnpm`，可以改用 Corepack：

```bash
corepack enable
corepack pnpm --version
```

如果你希望本机可以直接输入 `pnpm`，还可以执行：

```bash
corepack enable pnpm
```

仓库里的包装脚本，例如 `./web.sh`、`./gen_ts_bindings.sh` 和 `bash ./build.sh`，都会通过 `scripts/pnpm_cmd.sh` 自动解析 `pnpm`。如果环境里有可用的 Corepack，会优先使用 `corepack pnpm`；否则再回退到全局 `pnpm`。

参考：<https://pnpm.io/installation#using-corepack>

## 初始化

先安装工作区依赖：

```bash
pnpm install --frozen-lockfile
```

如果你选择的是 Corepack 方式，请把文档里的 `pnpm` 替换成 `corepack pnpm`。

前端会直接引用 `landscape-types` 中的生成代码，因此在开始前端开发前，需要先生成一次：

```bash
./gen_ts_bindings.sh
```

`./gen_ts_bindings.sh` 会导出 `openapi.json` 并重新生成 TypeScript client。修改了后端 OpenAPI 路由或 schema 之后，需要重新执行一次。

直接执行 `./gen_ts_bindings.sh` 时，默认总是强制重新导出并重新生成。

`bash ./build.sh -t <arch>` 不同：它内部会调用 `./gen_ts_bindings.sh --if-stale`，这样重复执行整仓构建时，只要生成产物和 lock 文件已经存在，就不会重复生成。

`./web.sh` 也会在启动前端 dev server 前调用 `./gen_ts_bindings.sh --if-stale`，这样前端开发时也能避免每次启动都重复生成。

如果你希望在完整构建流程之外也显式使用这种基于 lock 的跳过行为，可以用：

```bash
./gen_ts_bindings.sh --if-stale
```

只有当 `landscape-types/openapi.json`、`landscape-types/src/api/schemas/index.ts` 和 `landscape-types/.bindings.lock` 都存在时，它才会跳过；任意一个缺失都会重新生成。

## 日常开发

### 后端

```bash
cargo build --workspace
cargo test --workspace                              # 单元测试
cargo test -p landscape-ebpf --features bpf-test    # eBPF 集成测试（需要 root）
```

### 前端

```bash
./web.sh
```

`./web.sh` 会在启动 `landscape-webui` 开发模式前执行同样的基于 lock 的 API 类型检查。

等价原生命令：

```bash
pnpm --filter landscape-webui dev
```

如果前端报 `@landscape-router/types/...` 缺失，先重新生成 `openapi.json` 和 `landscape-types`。

`pnpm --filter landscape-webui build` 只负责构建前端应用本身。后端实际服务的 Scalar 静态资源整理属于 release-style 打包流程，由 `bash ./build.sh -t <arch>` 负责。

## 整仓构建

需要跑完整链路时执行：

```bash
bash ./build.sh -t x86_64
```

`build.sh` 会安装前端依赖，只在生成产物或 lock 文件缺失时重新生成 API 类型，构建 Web UI、把 Scalar 静态资源整理到 `output/static`，然后再构建 release 后端二进制。

## `sudo`

依赖安装、格式化、类型生成、普通前端构建和普通 Rust 编译都不需要 `sudo`。

只有在真实主机上运行 `landscape-webserver`、挂载 eBPF、操作真实网卡，或验证真实路由与 packet path 行为时才使用 `sudo`。

## 提交前检查

```bash
cargo fmt --all
cargo test --workspace
cargo test -p landscape-ebpf --features bpf-test
pnpm --filter landscape-webui exec prettier --check "src/**/*.{vue,ts,js,json,css,scss}"
pnpm --filter landscape-webui build
```
