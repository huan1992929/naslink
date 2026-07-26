# NASLink License Center 0.3.0

授权中心必须部署在产品方控制的 Linux 主机，Ed25519 私钥不得复制到客户 NAS 或合作方环境。

```bash
export NASLINK_LICENSE_ADMIN_TOKEN='至少16位随机管理令牌'
./naslink-license-center \
  -listen 0.0.0.0:17900 \
  -data-dir /var/lib/naslink-license \
  -private-key /etc/naslink/license-private.pem
```

启动后访问 `http://服务器:17900`，输入管理令牌即可在网页中管理客户、激活码、设备、续期、吊销和迁移。

建议使用 HTTPS 反向代理，仅公开 `/api/v1/activate` 与 `/api/v1/validate`；`/api/v1/admin/*` 限制到管理网络，并通过 `Authorization: Bearer <token>` 访问。

客户 SPK 每 6 小时校验一次在线 License。授权中心不可达时保留最近一次有效状态；明确吊销或迁移后，SPK 停止受 License 控制的新增同步操作，但不会删除 DSM 账号或文件。
