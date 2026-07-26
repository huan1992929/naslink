# NASLink 二期架构

```text
                 钉钉 / 企业微信（主身份源二选一）
               ┌── OAuth 登录
               ├── 部门 / 员工通讯录
               ├── 应用 Access Token
               └── Stream / 加密回调人员变动
                         │
                         ▼
┌────────────── NASLink SPK ──────────────┐
│  Web Console / Admin Session / CSRF               │
│                                                    │
│  Directory Store ── Matching Engine                │
│        │                  │                          │
│        └── Lifecycle Planner ── Sync Executor          │
│                                                    │
│  OIDC Provider    Event Ledger    Audit / Runs      │
└──────────────────────────────────────────────────┘
              │                           │
       DSM WebAPI HTTPS                 DSM OIDC Client
              │                           │
              ▼                           ▼
       DSM 本地用户 / 群组          DSM / Drive Web

产品方独立授权中心：客户 → 激活码 → 设备 → 签名 License
```

## 持久化

一期不引入外部数据库，所有数据位于 DSM 套件持久目录：

- `config.json`：管理员密码哈希、DSM、身份源、OIDC 与授权中心配置；
- `secrets.key`：AES-GCM 本地加密密钥；
- `state.json`：通讯录、匹配、部门映射、同步与审计记录；
- `oidc-private.pem`：OIDC RS256 签名私钥；
- `license.json`：离线签名 License；
- `naslink.log`：服务日志。

授权中心使用独立 `license-center.json`，私钥仅通过进程参数加载，绝不进入 SPK。

在线 License 每 6 小时调用授权中心 `/api/v1/validate`。网络失败保持最近一次状态；中心明确返回吊销、过期或设备不存在时，本地将该 License 标记为不可用。离线 License 不执行在线吊销，适合隔离网交付，控制依赖到期时间与后续升级包。

配置与状态使用原子替换写入，避免断电后出现半个 JSON 文件。

## 身份和同步分离

- OIDC 只解决“当前登录者是谁”；
- 企业微信工作台到 Drive Web 使用服务端 5 分钟一次性票据衔接；浏览器不接触 DSM 密码或可复用身份令牌；
- 企业微信免登入口只跳转到管理员保存的 Drive Web 地址，并在签发 OIDC 身份前复核通讯录在职状态与固定账号绑定；
- 固定绑定决定该身份对应哪个 DSM 用户；
- DSM WebAPI 负责账号存在性、启停状态和群组关系；
- NASLink 不传递、伪造 DSM SID。

## 人员变动

- 钉钉使用官方 `dingtalk-stream-sdk-go` 订阅人员与部门事件；
- 企业微信回调先校验 `msg_signature`，再使用 EncodingAESKey 解密；
- 事件不直接信任局部字段，而是触发全量权威目录校准；
- 默认只生成 `event-preview` 差异计划；管理员可显式开启 `auto_apply_events` 自动执行，仍受 License、保护账号和无删除路径约束；
- 每条事件保存在 `source_events`，处理失败可审计。

## 匹配与冲突

匹配规则是可解释的确定性评分：

- 企业邮箱完全一致：100；
- 工号与 DSM 用户名一致：100；
- 邮箱前缀与 DSM 用户名一致：85；
- DSM 描述与姓名一致：55；
- DSM 描述包含姓名：30；
- 管理员群组：-60 并禁止自动修改。

多候选同分或多员工占用同一 DSM 账号时，必须人工处理。

## 同步状态机

```text
preview ──确认词──> running ─┬─> completed
                                └─> partial ──> retry-preview
```

动作集只包含：

- `create_user`；
- `enable_user`；
- `disable_user`；
- `set_groups`。

不存在 `delete_user`。

## 版本适配边界

`SYNO.API.Info` 和 `SYNO.API.Auth` 有公开文档，但 `SYNO.Core.User` 与 `SYNO.Core.User.Group` 属于 DSM 内部 WebAPI。所有调用集中在 `internal/dsm`，真机测试如发现 DSM 7.2.x 参数差异，只替换该适配层，不改动匹配和同步引擎。
