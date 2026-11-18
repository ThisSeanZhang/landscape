# 构建与本地开发

本文件用于说明仓库的本地开发流程。如与 [BUILD.md](./BUILD.md) 不一致，以英文版为准。

## 该用什么命令

在仓库中运行 `just --list` 查看可用任务。Debian 13 可用 `sudo apt install just` 安装。

- 首次开发运行 `just init`，日常后端开发使用 `just build` 和 `just test`，前端开发服务器用 `./web.sh` 启动。
- 格式化使用 `just fmt`，可传入 `--rust` 等选项。Containerlab 端到端测试使用 `just e2e`，也可以用 `just e2e-gateway` 等任务单独运行一组用例。
- 整仓联调或发布使用 `./build.sh -t <arch>`。它会重建前端、整理静态资源并构建后端。

## 环境要求

- Linux 内核 `6.12+`
- 启用 BTF/BPF
- Node.js `22+`
- Rust 工具链（通过 [`rust-toolchain.toml`](./rust-toolchain.toml) 固定为 `1.98.0`）
- Clang/LLVM `19+`。Clang 18 及更早版本虽然能编译 BPF 源码，但不会生成
  eBPF arena 所需的 `BPF_ADDR_SPACE_CAST`，内核 verifier 会以
  `Permission denied` 拒绝加载。

系统依赖安装（Debian 13）：

```bash
sudo apt-get update
sudo apt-get install -y cmake clang-19 clang-format-19 lld-19 llvm-19 libclang-19-dev \
  gcc g++ make pkg-config libelf-dev libzstd-dev zlib1g-dev
export CLANG=clang-19
```

## pnpm 与 Corepack

仓库在 [`package.json`](./package.json) 里锁定了 `pnpm` 版本。如果你没有全局安装 `pnpm`，启用 Corepack：

```bash
corepack enable
corepack pnpm --version
```

仓库脚本（如 `./web.sh`、`./gen_ts_bindings.sh`、`bash ./build.sh`）通过 `scripts/pnpm_cmd.sh` 解析 `pnpm`，有可用 Corepack 时优先使用 `corepack pnpm`。参考：<https://pnpm.io/installation#using-corepack>。

## 初始化

安装工作区依赖并生成 TypeScript client：

```bash
just init
```

单独安装依赖可运行 `just pnpm install --frozen-lockfile`。

修改后端 OpenAPI 路由或 schema 后，需要重新执行 `just bindings`。`build.sh` 和 `./web.sh` 会以 `--if-stale` 调用它：只有当 `landscape-types/openapi.json`、`landscape-types/src/api/schemas/index.ts` 和 `landscape-types/.bindings.lock` 都存在时才跳过生成。

## 日常开发

### 后端

```bash
just build
just test        # 单元测试
just test-bpf    # eBPF 集成测试（需要 root）
```

`cargo tt` 和 `cargo ttb` 是上述两个任务对应的 Cargo 别名。BPF skeleton 会并行编译并按内容哈希缓存；内存受限的机器可用 `BPF_BUILD_JOBS` 限制 clang 并行度。

### 前端

```bash
./web.sh
```

`./web.sh` 会在启动 `landscape-webui` 开发模式前执行同样的基于 lock 的 API 类型检查。

如需直接启动已生成绑定的前端：

```bash
just pnpm --filter landscape-webui dev
```

如果前端报 `@landscape-router/types/...` 缺失，先重新生成 `openapi.json` 和 `landscape-types`。

`just web` 只负责构建前端应用本身。后端实际服务的 Scalar 静态资源整理属于 release-style 打包流程，由 `./build.sh -t <arch>` 负责。

## 整仓构建

需要跑完整链路时执行：

```bash
./build.sh -t x86_64
```

`build.sh` 会安装前端依赖，只在生成产物或 lock 文件缺失时重新生成 API 类型，构建 Web UI、把 Scalar 静态资源整理到 `output/static`，然后再构建后端二进制。默认使用 `fast` Cargo profile（关闭体积优化以换取最快编译速度）。需要正式 release 产物时使用：

```bash
./build.sh -t x86_64 --release
```

## `sudo`

pnpm 依赖安装、格式化、类型生成、普通前端构建和普通 Rust 编译都不需要 `sudo`。

只有在真实主机上运行 `landscape-webserver`、挂载 eBPF、操作真实网卡，或验证真实路由与 packet path 行为时才使用 `sudo`。

## 提交前检查

格式化与测试清单见 [CONTRIBUTING.zh.md](./CONTRIBUTING.zh.md)。
