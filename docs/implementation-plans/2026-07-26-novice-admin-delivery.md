# NASLink 非 IT 管理员交付体验实施计划

## 0. 交付元数据

- Plan ID: `NASLINK-NOVICE-UX-20260726`
- Created by: Sol
- Date/time/timezone: 2026-07-26 / Asia/Shanghai
- Approved delivery mode: Sol 规划 + Terra 实施 + Sol 验收
- Repository: `NASLink Identity Bridge`
- Repository root: `/Users/yunchengxiang/Desktop/code/群晖`
- Baseline branch: `main`
- Baseline commit: `0ead2d90c3550a2c61649ba33aae7ed775a6bd13`
- Dirty files intentionally included: 本计划文件
- Dirty files explicitly excluded: `.owner/`、`build/`、`dist/`、`output/`、Playwright 历史证据、Hallmark 本地资源
- Terra model/effort: `gpt-5.6-terra` / `high`
- Overall acceptance profile: `STANDARD`
- Strict milestones: M1 管理员认证与状态持久化；M3 同步启用、写前复核和 Drive/OIDC
- Production authorization: NOT GRANTED

## 1. 目标与完成定义

### 用户结果

不理解 DSM API、OAuth、OIDC 的企业行政或综合管理员可以：

1. 首次进入后按照唯一推荐动作完成配置；
2. 中途退出后继续上次步骤；
3. 看懂缺少的权限、数据或配置并直接前往处理；
4. 安全确认已有账号、预览写入影响并启用同步；
5. 把 Drive 免登录作为可选步骤配置和测试；
6. 日常只处理异常、冲突和待确认变更。

### 完成定义

- 已实现：M1–M4 均有提交、测试和 `ACCEPTANCE_PACKET`。
- 已验收：Sol 完成增量代码验收、完整 Go 回归、关键浏览器旅程和代表性失败态。
- 未部署：本轮不覆盖安装家庭 DS920+、真实钉钉/企业微信授权、DSM 用户写入或正式发布。

## 2. 范围

### In scope

- 首次初始化密码确认、用途说明和初始化后进入向导。
- 持久化 onboarding 状态、完成度、阻塞原因和推荐下一步。
- DSM、钉钉、企业微信的“保存并检测”新手流程。
- 通讯录范围选择、业务化账号匹配分组、同步预览和管理员密码确认。
- Drive 免登录分步助手、就绪检查和可观测测试状态。
- 首次配置模式与日常管理模式的导航重组。
- 健康首页、待处理事项和脱敏诊断包。
- 对应 Go 单元/接口测试、前端浏览器检查、文档和 SPK 构建验证。

### Non-goals

- 修改 DSM 内部未公开接口策略。
- 删除 DSM 用户、群组或文件。
- 自动提升部门负责人为 DSM 管理员。
- 绕过钉钉、企业微信或 DSM 的管理员授权。
- 新建 SaaS、多租户或外部数据库。
- 生产安装、真实人员同步、正式 License 签发或发布。

### Forbidden changes

- 不修改其他仓库。
- 不提交真实 AppKey、Secret、密码、员工数据或 License 私钥。
- 不执行生产部署、DSM 写操作、Git push、合并或历史重写。
- 不弱化现有保护账号、同步预览、计划陈旧校验、写后复核和永不删除边界。

## 3. 当前状态证据

- 产品能力与标准操作顺序：`README.md`。
- 易用性问题与 P0/P1/P2：`docs/PRODUCT_USABILITY_AUDIT_2026-07-26.md`。
- 非 IT 用户目标流程和文案：`docs/NOVICE_OPERATOR_PRODUCT_FLOW_2026-07-26.md`。
- 已有接口设计草案：`docs/NOVICE_UX_IMPLEMENTATION_PLAN_2026-07-26.md`。
- HTTP 路由、会话、同步执行和自动校准：`internal/server/server.go`。
- 当前管理界面：`internal/server/web/index.html`、`app.js`、`styles.css`。
- 配置与绑定：`internal/config/manager.go`。
- 状态、同步计划和匹配：`internal/state/`、`internal/syncengine/`。
- 当前基线：`./scripts/test.sh` 已通过 Go fmt、vet、race tests。

保留现有单 SPK、SQLite/文件状态、低权限 DSM WebAPI、OIDC Provider、匹配算法和同步执行器。新增体验层编排，不重写底层连接器。

## 4. 目标设计与契约

### 产品状态机

步骤：

`welcome -> dsm -> identity -> scope -> matches -> sync -> drive_optional -> complete`

每步状态：

`not_started | in_progress | blocked | complete | skipped`

后端根据真实配置和数据派生状态；前端不得把本地变量当作完成真相。状态需要保存当前步骤、身份源、Drive 是否跳过以及最后更新时间。

### API

实现或等价提供：

- `GET /api/v1/onboarding`
- `POST /api/v1/onboarding/start`
- `POST /api/v1/onboarding/dsm/connect`
- `POST /api/v1/onboarding/identity/connect`
- `POST /api/v1/onboarding/scope`
- `POST /api/v1/onboarding/matches/accept-safe`
- `POST /api/v1/onboarding/sync/enable`
- `POST /api/v1/onboarding/drive/skip`
- `POST /api/v1/onboarding/complete`
- `GET /api/v1/tasks`
- `GET /api/v1/support/diagnostics`
- `GET /api/v1/drive/readiness`
- `POST /api/v1/drive/preflight`

如果现有路由能组合完成动作，可复用内部函数，但面向向导的响应必须统一返回：

- `status`
- `title`
- `message`
- `blocking_reasons`
- `recommended_action`
- `counts`（适用时）

所有写接口必须保留 Session + CSRF。同步启用必须再次验证 NASLink 管理密码、检查计划新鲜度、重新盘点 DSM、执行后复核。

### 前端

- 未完成 onboarding 时，登录后进入全屏配置向导；不展示七个技术一级菜单。
- 每步仅一个主操作，辅助操作为保存退出、返回和技术详情。
- 高级地址、证书、UAT 前缀、OIDC 术语默认折叠。
- 空状态隐藏无意义的表格筛选和分页。
- 匹配结果分为：已找到原账号、需要确认、将创建、暂不处理。
- 完成后一级导航收敛为：首页、待处理、用户与部门、设置。
- 旧能力可作为子页保留，不删除现有诊断入口。

### 脱敏诊断

诊断输出只允许版本、能力名、连接状态、数量、错误类型和任务状态。不得包含密码、Secret、Token、手机号、邮箱、真实员工姓名、URL 查询凭据或 License 原文。

## 5. 里程碑

### M1 — Onboarding 状态与安全初始化（STRICT）

实现：

- 状态模型和持久化；
- onboarding 查询、开始、跳过 Drive、完成接口；
- 初始化密码确认、强度和用途说明；
- 初始化完成后进入向导；
- Session、CSRF 和管理员密码验证测试。

验收：

- 重启后步骤与选择保留；
- 未登录及缺 CSRF 写请求被拒绝；
- 两次密码不一致不可初始化；
- 已初始化系统不能重复初始化。

Sol action:

- `RERUN`: `go test -race ./internal/state ./internal/config ./internal/server`
- `INSPECT_ARTIFACT`: Terra 的 API 测试结果和状态文件匿名样例。

### M2 — 连接、范围与账号确认向导（STANDARD）

实现：

- DSM 和身份源保存并检测；
- 自动拉取或给出可执行权限修复信息；
- 全部在职/指定部门范围；
- 匹配业务分组和安全批量确认；
- 前置缺失的可操作空状态。

验收：

- 未配置、权限不足、零部门、匹配冲突均显示原因和下一动作；
- 高级字段默认收起；
- 批量确认不处理保护账号、多候选或重复绑定；
- 本里程碑不执行 DSM 写入。

Sol action:

- `RERUN`: `go test -race ./internal/dingtalk ./internal/wecom ./internal/syncengine ./internal/server`
- `INSPECT_ARTIFACT`: 关键页面截图与 API 响应。

### M3 — 同步启用、Drive 助手与待办（STRICT）

实现：

- 同步摘要和管理员密码确认接口；
- 计划陈旧时拒绝执行并返回新预览；
- Drive readiness/preflight 和分步助手；
- 待处理事项派生；
- 脱敏诊断包。

验收：

- 模拟 DSM 下验证新建、群组变更、禁用计划及写后复核；
- 无授权、计划过期、密码错误、Drive 未安装、用户未绑定均安全失败；
- 同步结果显示成功、失败、复核和下一次动作；
- 诊断包通过敏感字段测试。

Sol action:

- `RERUN`: `go test -race ./internal/server ./internal/dsm ./internal/oidc ./internal/syncengine`
- `RERUN`: 计划中的模拟 DSM 集成测试。
- `INSPECT_ARTIFACT`: Drive preflight 与诊断包样例。

### M4 — 日常工作台、集成回归和交付物（STANDARD）

实现：

- 完成后的四项导航；
- 健康首页、推荐动作和待办入口；
- 响应式与键盘基础；
- 更新 README、家庭测试指南和验收清单；
- 生成新的候选 SPK，但不安装。

验收：

- 新手关键旅程：初始化 → DSM 模拟连接 → 离线通讯录 → 范围 → 匹配 → 同步预览；
- 代表性失败旅程：身份源权限不足或同步计划陈旧；
- 刷新后继续当前步骤；
- 桌面与窄屏无阻断布局问题；
- `./scripts/test.sh`、`./packaging/spk/build.sh` 通过。

Sol action:

- `RERUN`: `./scripts/test.sh`
- `RERUN`: `./packaging/spk/build.sh`
- `RERUN`: 关键浏览器旅程和一个失败态。

## 6. 验收证据矩阵

| Requirement | Terra evidence | Sol action | Invalidation |
|---|---|---|---|
| 状态持久化与认证 | Go tests + packet | RERUN M1 targeted | state/config/session 修改 |
| 连接与权限引导 | API tests + screenshots | RERUN M2 targeted + inspect | connector/server/web 修改 |
| 安全匹配与范围 | matcher tests + grouped UI | RERUN matcher/server | matcher/policy/web 修改 |
| 同步安全 | mock DSM tests | RERUN strict integration | planner/DSM/apply 修改 |
| Drive/OIDC | provider/server tests | RERUN strict targeted | provider/config/web 修改 |
| 脱敏诊断 | response fixture + test | RERUN diagnostic test | diagnostics fields 修改 |
| 新手旅程 | browser evidence | RERUN critical journey | web/API/onboarding 修改 |
| 候选包 | build log + checksum | RERUN build once | packaging or source 修改 |

## 7. Sol 增量验收

每个里程碑先执行：

1. 核对 Worktree、基线、Commit 和 `ACCEPTANCE_PACKET`；
2. 查看 `git status`、文件列表、diff stat；
3. `git diff --check`；
4. 扫描秘密、真实人员数据、生产地址和越界修改；
5. 再执行该里程碑标记为 `RERUN` 的测试。

接受后记录 Commit。后续只审查从上一个接受 Commit 开始的差异；若触及共享的 `server.go`、状态模型、同步安全或前端全局入口，则使相关旧验收失效。

最终只运行一次完整回归、一次 SPK 构建、一个关键浏览器旅程和一个代表性失败态。真实 DS920+ UAT 留到用户单独授权的部署阶段。

## 8. 回滚与发布

- 所有实现位于 Terra Worktree 和分支，不自动合并。
- 本轮无数据迁移；若实现需要迁移，Terra 必须先暂停并由 Sol修订计划。
- 候选包只输出到忽略的 `dist/`。
- 发布、覆盖安装、真实 DSM 写入和身份源真实凭据验证均为独立授权门。

