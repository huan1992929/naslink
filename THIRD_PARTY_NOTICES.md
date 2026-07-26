# Third-party notices

NASLink 使用 Go 标准库并直接依赖钉钉官方 Stream SDK。下列公开项目用于实现或
核对协议、请求字段和 DSM 7 套件结构；发布物必须保留直接依赖的许可证声明。

| 项目 | 许可证 | 当前用途 |
|---|---|---|
| `N4S4/synology-api` | MIT | 核对 `SYNO.Core.User` 请求字段 |
| `janekbaraniewski/synoctl` | MIT | 核对 DSM 7 用户、群组接口名称与安全更新方式 |
| `Frizlab/officectl` | Apache-2.0 | 核对 Synology 用户创建请求体 |
| `SynoCommunity/spksrc` | BSD 类 | 参考 SPK 目录与构建流程 |
| `tailscale/tailscale-synology` | MIT | 参考 DSM 7 服务生命周期 |
| `zitadel/oidc` | Apache-2.0 | 参考 OIDC Provider 行为；当前未引入代码 |
| `larksuite/oapi-sdk-go` | MIT | 后续飞书适配候选；当前未引入 |
| `open-dingtalk/dingtalk-stream-sdk-go` | MIT | 已直接依赖，用于钉钉人员/部门事件 Stream 长连接 |
| `gorilla/websocket` | BSD-2-Clause | 由钉钉 Stream SDK 间接依赖 |
| `google/uuid` | BSD-3-Clause | 由钉钉 Stream SDK 间接依赖 |
| `ArtisanCloud/PowerWeChat` | MIT | 仅用于公开资料调研；未引入代码 |
| `olifolkerd/tabulator` 6.5.0 | MIT | 已离线内置，用于大型 DSM/通讯录表格的搜索、排序、响应式布局与分页；许可证位于 `internal/server/web/vendor/LICENSE.tabulator` |

不采用或不复制：

- `homebridge/homebridge-syno-spk`：GPL-3.0，仅作公开页面层面的调研；
- `topiam/eiam`：AGPL-3.0，不进入闭源商业产品；
- SSOTools 商业 SPK：仅根据公开产品说明定义验收行为，不反编译、不复制代码和素材。
