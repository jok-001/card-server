# XM Card Server · 多应用卡密验证系统

轻量级在线卡密验证服务端。纯 Python 标准库（3.6+，零第三方依赖）+ SQLite，单文件部署，
内置 Web 管理后台，支持**多应用隔离**——一台服务器可以同时为 N 个软件系统发卡，
各系统卡密互不共通。

> 特性一览
> - 卡密类型：日/周/月/季/年/永久，未激活卡不计时（首用起算）
> - 设备绑定：一卡限 N 台设备（发卡时可调），后台一键解绑
> - 管理后台：发卡 / 封禁解封 / 解绑 / 续期 / 删除 / 批量操作 / 按卡密·备注·设备号搜索 / 验证日志
> - 账户登录：PBKDF2 口令 + HMAC 会话 Cookie，失败锁定
> - 安全：请求 HMAC 签名 + 响应门禁签名（防篡改/防伪造）+ 每 IP 限速
> - 脚本密钥下发（`/key`）：可选能力，客户端解密密钥只在卡密有效时下发
> - 多应用隔离：每个应用独立 ks/gk 密钥，互不共通，支持一键换钥全网失效
> - 每日自动备份数据库（保留 7 份）

## 快速开始

```bash
# 1. 上传到服务器（任意有 Python 3.6+ 的 Linux/Windows）
# 2. 直接运行
python3 app.py
# 首次运行自动生成 config.json（随机密钥），控制台会打印管理后台账号密码

# 3. 验证
curl http://127.0.0.1:8080/health      # -> ok

# 4. 浏览器打开管理后台
http://<服务器IP>:8080/
```

详细部署（systemd 常驻、安全组、迁移）见 [`docs/部署指南.md`](docs/部署指南.md)。

## 客户端如何接入

你的软件（无论 Python / JS / Android 脚本引擎）只需三步接入：

1. 管理后台 →「应用管理」→ 新建应用（自动生成该应用专属 ks/gk）
2. 把 ks/gk 写进你的客户端
3. 用 SDK 参考实现发起卡密验证（约 40 行代码）

完整协议说明 + Python / JavaScript(AutoJs6) 双端参考实现见
**[`docs/SDK接入指南.md`](docs/SDK接入指南.md)** 与 [`sdk/`](sdk/) 目录。

## 目录结构

```
xm-card-server/
├── app.py               服务端全部逻辑（HTTP/协议/校验/管理 API）
├── admin.html           管理后台单页（无构建、无外部依赖）
├── config.example.json  配置样例（首次运行自动生成 config.json，也可照抄改）
├── card.service         systemd 单元（Linux 常驻）
├── smoke_test.py        部署自检脚本（对运行中的实例跑全量协议测试）
├── sdk/
│   ├── client_example.py   Python 客户端参考实现
│   └── card_client.js      JS/AutoJs6 客户端参考实现
└── docs/
    ├── 部署指南.md
    ├── 运维手册.md
    └── SDK接入指南.md
```

## 配置说明（config.json）

| 键 | 说明 |
|---|---|
| `port` | 监听端口 |
| `admin_token` | 管理 API 凭证（脚本调用用） |
| `admin_user` / `admin_pass` | 后台登录账户（pass 为 PBKDF2 哈希） |
| `session_secret` | 会话 Cookie 签名密钥 |
| `ks` / `gk` | 默认应用（首个应用）的客户端签名密钥/响应门禁密钥 |
| `app_secret` | （可选）客户端侧签名校验密钥；不使用该签名机制则留空 |
| `build_key` | （可选）`/key` 脚本密钥下发能力使用的密钥 |
| `max_devices_default` | 发卡默认每卡设备数上限 |
| `rate_limit_per_min` | 每 IP 验证请求限速（次/分钟） |

改 `ks/gk/port` 后需重启服务；客户端同步更新即完成"全网换锁"。

## 安全模型

- 卡密、签名密钥只在服务端，客户端只持 ks/gk（泄露可后台一键轮换全网失效）
- 客户端请求带 HMAC-SHA256 签名（ks），服务端据此识别应用并防扫描
- 服务端响应带 HMAC-SHA256 门禁（gk），客户端验签后才采信——防中间人篡改与本地伪造
- 管理后台口令 PBKDF2 存储，会话 Cookie HttpOnly + 签名，登录失败 10 次锁 10 分钟
- `/f` `/n` `/key` 每 IP 限速，卡号空间 31⁹ ≈ 10¹³，枚举不现实

诚实边界：ks/gk 编译进客户端（虽然是密文形态），决心足够者可逆向提取后自建假响应。
建议定期轮换 ks/gk；对高价值场景可将客户端验签逻辑做白盒/虚拟化加固。

## License

MIT
