# 企业微信自建应用接入 Synology Drive Web

## 目标

员工在企业微信工作台点击“企业网盘”后，NASLink 静默取得当前企业成员 `UserId`，校验人员状态与群晖账号绑定，再借助 DSM 原生 OIDC 登录进入 Synology Drive Web。整个过程不保存、传递或模拟员工的 DSM 密码。

```text
企业微信工作台
  → /launch/wecom/drive
  → 企业微信 snsapi_base 静默授权
  → /auth/wecom/drive/callback
  → 5 分钟一次性登录票据
  → Synology Drive Web
  → DSM OIDC /oidc/authorize
  → DSM 会话与 Drive Web
```

## NASLink 配置

在“连接配置”中完成：

1. 主身份源选择“企业微信”；
2. 填写自建应用的 Corp ID、Agent ID、Secret；
3. 应用内静默授权地址保留默认值 `https://open.weixin.qq.com/connect/oauth2/authorize`；
4. 填写员工实际访问的 Synology Drive Web 完整 HTTPS 地址；
5. 配置 OIDC Issuer、DSM Client ID、Client Secret 与 DSM 返回的 Redirect URI；
6. 保存后复制后台生成的“自建应用主页”地址。

Drive Web 地址是管理员保存的固定目标，启动接口不接受用户传入任意跳转地址，避免开放重定向。

## 企业微信后台配置

1. 创建企业内部自建应用，名称可设为“企业网盘”；
2. 应用主页填写 NASLink 生成的 `https://你的NASLink域名/launch/wecom/drive`；
3. 网页授权及 JS-SDK 可信域名填写 NASLink Issuer 使用的域名；
4. 应用可见范围至少包含参加测试的员工；
5. 通讯录 API 权限应覆盖需要同步的部门和成员；
6. 如启用实时人员变动，将 NASLink 显示的 `/events/wecom` 配为接收消息服务器 URL，并使用相同 Token 与 EncodingAESKey。

企业微信网页授权的回调域名必须与应用可信域名匹配。第一轮测试建议只开放给 1 个测试部门和 2 至 5 名员工。

## DSM 与 Synology Drive 配置

1. 安装并启用 Synology Drive Server；
2. 在 DSM 中启用 OIDC SSO Client；
3. Discovery URL 使用 NASLink 后台显示的 `/.well-known/openid-configuration`；
4. DSM Client ID、Client Secret 与 NASLink 中保存的值保持一致；
5. 用户名 Claim 使用 `username` 或 `preferred_username`；
6. 确认测试 DSM 账号有 Synology Drive 应用权限；
7. 把用户实际打开的 Drive Web 地址保存到 NASLink。

NASLink 负责员工身份、在职状态和 DSM 账号绑定；最终的 Synology Drive 应用访问权限仍由 DSM 自身执行。

## 放行条件

下列条件全部满足才签发 DSM OIDC 身份：

- 当前主身份源为企业微信；
- 企业微信返回企业内部成员 `UserId`，而不是外部联系人 OpenId；
- 最近一次 NASLink 通讯录中存在该员工且状态为在职；
- `userid:<UserId>` 已绑定唯一 DSM 用户名；
- OIDC Client 与 Redirect URI 已登记；
- 一次性登录票据未过期且未使用。

员工离职、停用、被移出当前通讯录或账号未绑定时，NASLink 显示明确错误页并写入审计日志。

## 安全与会话边界

- 企业微信启动事务有效期 10 分钟；
- DSM 接力票据有效期 5 分钟，存放在服务端内存中且只能使用一次；
- 浏览器只持有 HttpOnly、SameSite=Lax Cookie；生产 HTTPS 环境自动加 Secure；
- OIDC `state`、`nonce`、Client ID 与 Redirect URI 仍按原协议校验；
- NASLink 重启后未完成的一次性票据自然失效，员工重新点击工作台应用即可；
- 此能力面向 Synology Drive Web，不代表 Windows/macOS Synology Drive Client 可以免密绑定。

## 家庭测试顺序

1. 先同步企业微信通讯录并确认测试员工为“在职”；
2. 在“账号匹配”中把该员工绑定到一个现有测试 DSM 账号；
3. 用普通浏览器验证 DSM OIDC 基础登录；
4. 再在企业微信手机端点击“企业网盘”；
5. 确认无需扫码并进入 Drive Web；
6. 再次访问确认可重新完成新事务；
7. 把测试员工标记停用或解除绑定，确认访问被拦截；
8. 检查 NASLink 审计日志包含 `wecom_drive_launch` 和 `oidc_login`。

