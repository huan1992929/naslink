# NASLink 全流程模拟测试报告

测试时间：2026-07-17  
测试版本：0.3.0-rc1  
测试方式：NASLink 本地服务 + 有状态 DSM WebAPI 模拟器 + 真实管理后台交互

## 结论

核心账号生命周期闭环通过。系统成功完成 DSM API 发现、账号盘点、通讯录导入、历史账号匹配、部门群组映射、差异预览、确认执行、重复同步幂等、前缀安全拦截、重启持久化与 DSM 离线异常处理。

本轮不等于真实 DS920+ 兼容验收，也未连接真实钉钉、企业微信或 Synology Drive Web。

## 模拟数据

模拟 DSM 初始包含：

- 7 个本地账号；
- 5 个本地群组；
- 1 个需要调岗的员工；
- 1 个需要创建的新员工；
- 1 个需要离职禁用的员工；
- 1 个需要重新启用的员工；
- `admin`、`guest` 和 NASLink API 管理账号作为保护账号。

模拟通讯录包含 3 个部门、5 名员工，其中 4 名在职、1 名离职。

## 执行结果

| 场景 | 预期 | 结果 |
|---|---|---|
| DSM API 自动发现 | 发现 Auth、User、Group 等能力 | 通过 |
| DSM 只读盘点 | 读取 7 用户、5 群组 | 通过 |
| 通讯录导入 | 导入 3 部门、5 用户 | 通过 |
| 历史账号匹配 | 4 个已有账号高可信匹配 | 通过 |
| 部门群组映射 | 3 个部门映射对应 DSM 群组 | 通过 |
| 调岗 | `zhangsan` 从 `dept_design` 调整到 `dept_sales` | 通过 |
| 入职 | 创建 `naslink_poc_003` 并加入 `dept_design` | 通过 |
| 离职 | 将 `wangwu` 设置为禁用 | 通过 |
| 重新入职 | 将 `zhaoliu` 从禁用恢复为启用 | 通过 |
| 同步执行 | 5 项成功、0 项失败 | 通过 |
| 幂等性 | 第二次预览为 0 项 | 通过 |
| 保护前缀 | 拦截 `production_user` | 通过 |
| 管理员保护 | 未修改 `admin`、`guest`、API 管理账号 | 通过 |
| 重启持久化 | 策略、匹配、同步记录重启后保留 | 通过 |
| DSM 离线 | 显示连接失败，前端不崩溃 | 通过 |
| 前端控制台 | 无 error / warning | 通过 |

## 最终模拟 DSM 状态

```text
naslink_poc_003  启用  dept_design, users
wangwu           禁用  users, dept_design
zhangsan         启用  dept_sales, users
zhaoliu          启用  users, dept_sales
```

模拟 DSM 共收到 5 个写操作，且不存在删除账号、删除群组或删除文件请求。

## 本轮发现的问题

### P1：匹配结果的解释被覆盖

高可信自动匹配完成后，页面显示状态为 `confirmed`，但匹配依据被改写为“管理员人工确认”。这会影响审计解释，应区分 `auto-confirmed` 与人工确认。

### P1：自动匹配后绑定列表没有即时刷新

自动匹配已经写入绑定配置，但“已确认绑定”区域仍显示 0，刷新页面后才会更新。重新计算匹配成功后应同时重新加载绑定配置。

### P2：同步完成后账号盘点页仍显示旧快照

同步执行完成后，进入账号盘点页仍展示执行前状态，必须手动点击“重新盘点”。建议执行成功后自动刷新盘点，或明确显示“快照生成时间 / 需要重新盘点”。

### P2：DSM 离线错误信息过于底层

当前直接显示完整 `dial tcp ... connection refused`。功能正确，但客户界面应转换为“无法连接群晖，请检查地址、端口、证书和网络”，底层信息放入详情或日志。

## 测试资产

- 模拟 DSM：[tools/mockdsm/main.go](../tools/mockdsm/main.go)
- 模拟通讯录：[docs/simulation-directory.json](simulation-directory.json)
- 同步预览截图：[01-sync-preview.png](../output/simulation-2026-07-17/01-sync-preview.png)
- 执行完成截图：[02-sync-completed.png](../output/simulation-2026-07-17/02-sync-completed.png)
- 最终账号盘点：[03-final-inventory.png](../output/simulation-2026-07-17/03-final-inventory.png)

## 下一步

下一轮应在 DS920+ 上按相同测试数据执行：只读盘点、`naslink_poc_` 测试账号创建、禁用、恢复、群组调整。通过后再接真实钉钉测试应用和 DSM OIDC / Synology Drive Web。
