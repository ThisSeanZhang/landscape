# Landscape WebUI

前端使用 Vue 3、TypeScript 和 Pinia。从本目录运行 `pnpm dev` 启动开发服务，`pnpm test` 运行测试，`pnpm build` 执行类型检查并构建生产包。

## 源码目录

| 目录              | 内容                                     |
| ----------------- | ---------------------------------------- |
| `src/router`      | 路由、导航菜单和路由守卫                 |
| `src/layouts`     | 主布局和侧栏                             |
| `src/views`       | 路由对应的页面                           |
| `src/components`  | 按功能分组的界面组件，包括设置卡片和图表 |
| `src/composables` | 可复用的 Vue 响应式逻辑和生命周期管理    |
| `src/stores`      | Pinia store 和共享状态                   |
| `src/api`         | API 调用、拦截器和响应转换               |
| `src/lib`         | 前端领域逻辑、表单默认值和通用工具       |
| `src/i18n`        | 中英文界面文案                           |

## API 类型与表单

接口请求、响应和枚举从 `@landscape-router/types/api/schemas` 导入。新增表单时，默认值可以放在返回该 schema 类型的工厂函数里。拓扑虚拟节点、补齐默认值的 WAN 表单等需要额外字段或方法，可在对应领域模块中用生成类型派生前端模型。

同目录模块使用相对路径，跨目录引用可使用 `@/` 指向 `src/`。测试与被测模块放在一起。

提交 JSON 请求时，可选字段需要省略的，在对应 API 适配函数中转换为 `undefined`。可空字段按 schema 保留 `null`，必填字段在表单中校验。例如设备登记允许省略未填的 IP 地址，同时需要保留空标签列表 `tag: []`。
