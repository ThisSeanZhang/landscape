# Landscape 贡献指南

感谢你对 Landscape 的关注。Landscape 是一个基于 eBPF 的 Linux 路由平台 — 欢迎 Rust、C/eBPF、TypeScript/Vue 以及文档等各方面的贡献。

[English](./CONTRIBUTING.md)

## 行为准则

请保持尊重。讨论应聚焦于技术本身，保持建设性。

## 如何贡献

### 报告 Bug

请使用 [Bug 报告模板](https://github.com/ThisSeanZhang/landscape/issues/new?template=bug-报告模板---bug-report-template.md)。需包含：

- 操作系统、内核版本、软件版本
- 精确的复现步骤
- 预期结果与实际结果
- 相关日志或截图

### 请求新功能

请使用 [功能请求模板](https://github.com/ThisSeanZhang/landscape/issues/new?template=功能请求模板---feature-request-template.md)，说明使用场景以及现有功能为何不满足需求。

假设想要贡献一个新功能，不妨先发起一个 Issue 说明一下思路。这样既能避免和其他贡献者重复劳动，也方便在投入较多时间之前一起讨论方案。

### 提议改进

请使用 [功能请求模板](https://github.com/ThisSeanZhang/landscape/issues/new?template=功能请求模板---feature-request-template.md)，清楚说明动机和影响范围。

### 新手贡献者

可以关注标记为 `good first issue` 或 `help wanted` 的 Issue。

## 开发环境搭建

系统依赖、pnpm 配置、初始化以及日常构建命令见 [BUILD.zh.md](./BUILD.zh.md)。

## PR 提交前必做

**每次提交 PR 前必须格式化代码。** 运行格式化脚本以确保代码通过 CI 检查：

```bash
./fmt.sh
```

这会运行全部三种格式化器（Rust、C/eBPF、前端）。也可以只格式化某一种语言：

```bash
./fmt.sh --rust      # 仅格式化 Rust（cargo fmt）
./fmt.sh --c         # 仅格式化 C/eBPF（clang-format-18）
./fmt.sh --frontend  # 仅格式化前端（prettier）
```

然后执行完整的 PR 检查清单：

```bash
cargo test --workspace
cargo test -p landscape-ebpf --features bpf-test   # eBPF 集成测试（需要 root）
pnpm --filter landscape-webui run format:check
pnpm --filter landscape-webui build
```

## 代码规范

### 通用

- 遵循所编辑文件已有的代码风格。
- 非必要不引入新依赖。
- PR 应聚焦：每个 PR 只包含一个逻辑变更。

### Rust

- 使用 `./fmt.sh --rust` 或 `cargo fmt` 格式化。项目配置了 [`.rustfmt.toml`](./.rustfmt.toml)。
- 为新逻辑编写测试。运行 `cargo test --workspace` 验证。
- 新增 API 类型时，遵循 `landscape-common` 的序列化约定。
- 如果修改了 OpenAPI 路由或 schema，运行 `./gen_ts_bindings.sh` 更新本地绑定。
- `landscape-common` 中按域组织类型，同一域内按数据生命周期分文件：
  - `config.rs`：静态入库配置（DB/文件真相，及嵌套序列化项与校验）。
  - `runtime.rs`：由静态配置与环境解析后、服务实际消费的运行期形状。
  - `api.rs`：HTTP/OpenAPI 边界 DTO（`*Request`/`*Response`/`Query*`/`*Payload`）。
  - `status.rs` / `info.rs`：只上报 UI 的可观测状态，不作为配置消费。
  - `dataplane.rs`：将运行期配置下发内核。`error.rs`：域内错误。`mod.rs` 只做模块声明与 `pub use` 再导出。

### C / eBPF

- 使用 `./fmt.sh --c` 或 `clang-format-18` 格式化。项目配置了 [`.clang-format`](./.clang-format)。
- eBPF 程序位于 `landscape-ebpf/src/bpf/`。不要格式化自动生成的 `vmlinux.h`。
- 确保 BPF 程序兼容 [BUILD.zh.md](./BUILD.zh.md) 中记录的内核版本。

### TypeScript / Vue

- 使用 `./fmt.sh --frontend` 或 `prettier` 格式化代码。
- 严格使用 TypeScript。前端通过 `vue-tsc` 进行类型检查。
- `landscape-types/` 中的 API 客户端代码由 [orval](https://orval.dev/) 从 `openapi.json` 自动生成，请勿直接编辑。

### 提交信息

无严格格式要求，但建议使用：

```
<模块>: <简要描述>

<可选详细说明>
```

示例：`ebpf: 修复接口断开时 NAT4 规则泄漏`，`webui: 添加深色模式切换`。

## 项目结构

| 目录 | 用途 |
|---|---|
| `landscape/` | 核心库（配置、NAT、DNS、eBPF 集成） |
| `landscape-webserver/` | HTTP/HTTPS 服务、REST API、WebSocket |
| `landscape-ebpf/` | eBPF C 程序 + Rust 用户态加载器 |
| `landscape-database/` | SeaORM 数据库 schema + SQLite 指标存储 |
| `landscape-gateway/` | 基于 Pingora 的网关 |
| `landscape-dns/` | 基于 hickory 的 DNS 服务 |
| `landscape-common/` | 共享工具库、OpenAPI 支持 |
| `landscape-macro/` | 过程宏 |
| `landscape-protobuf/` | Protobuf 定义 |
| `landscape-types/` | 自动生成的 TypeScript API 客户端 |
| `landscape-webui/` | Vue 3 + Vite 前端 |

## CI 构建与发布分支

`build and release` workflow（`.github/workflows/build-and-release.yml`）会根据推送的 ref 选择构建范围：

| Ref | 原生 x86_64 / aarch64 | 交叉编译 target | 发布 Release |
| --- | --- | --- | --- |
| `build` | 是 | 否 | 否 |
| `build-all` | 是 | 全部 | 否 |
| `v*` tag | 是 | 全部 | 是 |
| 其他 tag | 是 | 否 | 否 |

全量构建包含原生 target，以及 musl（`x86_64`、`aarch64`、`riscv64`、`loongarch64`）和 gnu（`riscv64`、`s390x`、`loongarch64`）交叉编译 target。

## 有疑问？

可以在 [Question 讨论区](https://github.com/ThisSeanZhang/landscape/issues/new?template=疑问---questions.md) 提问，或查阅[项目文档](https://landscape.whileaway.dev/en/)。
