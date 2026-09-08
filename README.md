# NASLink for DingTalk / WeCom / Synology DSM

NASLink 是一个面向 DSM 7 的低权限 SPK，将钉钉或企业微信组织、人员变动、群晖本地账号生命周期、Synology Drive Web 单点登录集成在一个安装包内。

当前版本是 **0.3.0-rc19，二期商品版候选**。本版把账号匹配、同步计划、执行和 DSM 结果复核收敛为引导式工作流；修复 DSM 群组成员写入接口，并把“成功”定义为写入后重新读取到目标状态。人工同步执行期间会跳过定时校准，避免产生过期计划。钉钉与企业微信的接入、历史账号保护和“永不自动删除账号或文件”的安全边界保持不变。

## 已实现

- 单 SPK 部署，不需要 Docker、Redis 或外部数据库；
- DSM API 自动发现、登录、用户/群组只读盘点；
- 钉钉或企业微信作为单一主身份源，登录和 OIDC Provider；
- 两个平台的全量部门、员工通讯录拉取；
- 钉钉官方 Stream SDK 人员/部门事件长连接；
- 企业微信 SHA1 验签、AES-CBC 解密通讯录回调；
- 企业微信自建应用“企业网盘”主页入口，使用 `snsapi_base` 静默识别当前员工；
- 企业微信身份与 DSM OIDC 之间使用 5 分钟、一次性、HttpOnly 登录票据衔接，不保存或转交 DSM 密码；
- Synology Drive Web 固定目标地址、在职状态与账号绑定校验，离职或未绑定员工直接拒绝；
- 人员变动事件台账、失败记录和自动差异计划；
- 人员变动默认只生成预览；客户明确开启高风险开关后，可自动执行创建、禁用与群组调整；
- 通讯录 JSON 离线导入，可在无实机时演练；
- 邮箱、工号、邮箱前缀、姓名描述的可解释匹配评分；
- 多候选、重复绑定、管理员账号冲突拦截；
- 部门与 DSM 群组映射；
- 通讯录全量盘点与受管部门范围分离，不会默认把全公司写入 DSM；
- 受管部门缺少目标群组时，同步预览先列出群组创建动作；
- 识别钉钉与企业微信部门负责人，不自动提升 DSM 权限；
- DSM 账号/群组、部门、员工和匹配表支持本地搜索、筛选、排序、分页与响应式收起；
- 入职创建、在职恢复、离职禁用、调岗群组变更计划；
- 同步预览、人工确认执行、部分失败重试；
- 定时拉取并生成待确认校准计划；
- 本地审计日志、最近 100 次同步记录、状态备份；
- 30 天试用、安装实例指纹、Ed25519 离线 License 验签；
- 独立 License 签发 CLI 与可视化授权中心，支持客户、激活码、设备绑定、续期、吊销和迁移；
- 客户 SPK 每 6 小时在线校验吊销状态，授权中心临时离线不影响最近有效授权；
- 在线激活与离线 License 并存，签名私钥不进入 SPK；
- 响应式管理后台。

## 安全边界

- 系统没有“删除 DSM 用户”或“删除文件”代码路径；
- 正式同步必须先生成差异预览，再输入 `APPLY NASLINK SYNC`；
- `admin`、`guest`、API 管理员和 `administrators` 群组成员不会自动修改；
- 一个 DSM 账号不允许绑定多名员工；
- 新账号命名冲突时不会接管原有账号；
- 密钥和外部 Secret 使用 AES-GCM 加密，配置与状态文件权限为 `0600`；
- SPK 以套件低权限用户运行，不调用 `synouser` / `synogroup`，不要求 root；
- 订阅过期不会删除或回滚已有 DSM 账号。

## 标准操作顺序

```text
选择钉钉或企业微信并配置 DSM
      ↓
只读盘点 DSM
      ↓
拉取主身份源通讯录
      ↓
运行自动匹配
      ↓
管理员处理冲突并确认绑定
      ↓
配置部门群组
      ↓
生成同步预览
      ↓
确认执行
      ↓
配置 DSM OIDC、Drive Web 与企业微信自建应用主页
```

## 首次配置与日常管理

首次登录需设置并确认 NASLink 本地管理密码。随后按“连接群晖 → 连接企业通讯录 → 选择人员范围 → 确认账号 → 同步预览与启用 → 可选 Drive 免登录”继续；关闭后会保留进度。

完成首次配置后，一级入口收敛为“首页、待处理、员工与部门、设置”。同步仍必须先生成预览，并在启用时重新读取 DSM、拒绝陈旧计划、写入后复核。Drive 配置检查和支持诊断只返回状态、数量和错误类型，不导出密码、Secret、Token 或员工身份信息。

## 本地运行与测试

```bash
export PATH=/tmp/codex-go-1.26.5/go/bin:$PATH
go run ./cmd/naslink --listen 127.0.0.1:17890 --data-dir ./build/dev-data
```

打开 `http://127.0.0.1:17890`。

```bash
./scripts/test.sh
./packaging/spk/build.sh
```

输出位于 `dist/NASLink-0.3.0-0019-x86_64.spk`。

授权中心构建：

```bash
./packaging/license-center/build.sh
```

输出位于 `dist/NASLink-LicenseCenter-0.3.0-linux-amd64.tar.gz`。部署说明见压缩包内 README。

## License 签发

管理后台“系统授权”显示设备指纹。使用仅保存在产品所有者环境的私钥签发：

```bash
go run ./cmd/licensegen \
  -id LIC-2026-000001 \
  -customer '测试客户' \
  -device '后台显示的设备指纹' \
  -max-users 300 \
  -expires 2027-07-31 \
  -out customer-license.json
```

默认私钥位于 `.owner/license-private.pem`，已加入 `.gitignore`，不会被打包到 SPK。请对该文件单独做加密备份。

## 文档

- [安装与使用说明](docs/USER_GUIDE.md)
- [架构说明](docs/ARCHITECTURE.md)
- [DS920+ 家庭测试指南](docs/HOME_TEST_GUIDE.md)
- [DS920+ 实机安装测试报告](docs/DS920_LIVE_TEST_2026-07-18.md)
- [钉钉、企业微信与 DSM 验收清单](docs/ACCEPTANCE_CHECKLIST.md)
- [企业微信自建应用接入 Synology Drive Web](docs/WECOM_DRIVE_SSO.md)
- [开源依据与许可证](THIRD_PARTY_NOTICES.md)
