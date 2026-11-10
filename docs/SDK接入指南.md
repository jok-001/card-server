# SDK 接入指南

你的软件接入本卡密系统，只需三步：

1. **管理后台建应用**：浏览器打开 `http://<服务器IP>:8080/` 登录 → 「应用管理」→ 新建应用
   （自动生成该应用专属 `ks` / `gk`）
2. **客户端集成**：把 `ks` / `gk` 和服务器地址写进你的软件，套用本文参考实现（约 40 行）
3. **发卡**：后台选中该应用 → 发卡 → 卡密发给用户

> **多应用隔离**：每个应用有独立 ks/gk。A 应用的卡拿到 B 应用的客户端验证，
> 服务端直接返回"卡密不存在"。卡密、设备绑定、验证日志全部按应用隔离。

## 协议总览

| 通道 | 用途 | 请求体 | 响应体 |
|---|---|---|---|
| `POST /f` | 卡密验证（登录/心跳，通用） | `url ␁ body ␁ aid ␁ sign` | `gate ␍ r` |
| `POST /n` | EC netcard 兼容通道（bind/unbind/info） | `action ␁ card ␁ aid ␁ sign` | `gate ␍ r` |
| `POST /key` | 脚本解密密钥下发（可选能力） | `card ␁ aid ␁ sign` | `gate ␍ r` |

其中 `␁ = \x01`（0x01 分隔符），`aid` = 设备标识（用于一卡一机绑定）。

```
sign = HMAC-SHA256(key=ks, msg=除 sign 外的各段用 \x01 连接)   的 hex 小写
gate = HMAC-SHA256(key=gk, msg=r)                              的 hex 小写
```

- 请求签名 `sign` 不匹配 → `403`（防扫描/防垃圾流量）
- 响应门禁 `gate` 不匹配 → **客户端必须丢弃该响应**（防中间人篡改/本地伪造）
- 卡密无效时，`/f` 返回固定失败串 `{"code":10218,"message":"卡密不存在或已失效","result":null}`

## 卡号识别规则

服务端在 `url + body` 里用正则提取卡号：
`[A-Z0-9]{2,6}-XXXX-XXXX-XXXX`（X 为无混淆字符集 `2-9 A-H J-N P-Z`）。
你的客户端把卡密放进 body 的**任意字段**均可，如 `card=ABCD-1234-ABCD-1234`。

## 验证语义

| 情形 | 结果 |
|---|---|
| 卡不存在 / 已封禁 / 已过期 / 设备数超限 | 固定失败串（10218） |
| 未激活的有效卡 | **激活**（expire_at = now + 天数），返回成功 |
| 已激活有效卡 | 返回成功，同时刷新设备绑定与最后在线 |
| 断网 | 由客户端决定：可实现"最近成功缓存"宽限（参考实现已内置 48h） |

成功响应（/f）为双层 JSON：外层为传输包装（header/statusCode 等），内层为业务对象
`{code, message, result:{expires,...}, nonce, sign}`。
客户端只需关注内层 `code == 0` 与 `result.expires`；`nonce/sign` 为服务端防重放签名字段。

## Python 参考实现

见 [`sdk/client_example.py`](../sdk/client_example.py)：

```python
from card_client import CardClient

cc = CardClient(server="http://<服务器IP>:8080", ks="<你的ks>", gk="<你的gk>")
r = cc.verify("XXXX-XXXX-XXXX-XXXX")     # 自动签名 + 门禁验签 + 断网宽限
print(r.ok, r.message, r.expires)
```

## JavaScript / AutoJs6 参考实现

见 [`sdk/card_client.js`](../sdk/card_client.js)（Rhino/AutoJs6 兼容，JDK 直连 HTTP，
已处理 AutoJs6 `http.request` 不支持字符串 body 的坑）。核心调用：

```javascript
var card = require("./card_client.js");
var r = card.verify("XXXX-XXXX-XXXX-XXXX");
if (!r.ok) { toast(r.message); exit(); }
```

## 脚本密钥下发（/key，可选）

如果你的软件自身有"加密脚本/资源包"，可以把解密密钥放在服务端 `config.json` 的
`build_key`，客户端在卡密验证通过后调 `/key` 获取——**无有效卡密则拿不到密钥**。
参考实现里是 `fetchKey()`。

## 心跳建议

登录成功后每 15 分钟复验一次；失败先自动重登一次，仍失败再停止软件（参考实现
`startHeartbeat()` 已内置该语义）。

## 管理自动化（可选）

除网页后台外，所有管理操作都有 API（Header 带 `X-Admin-Token`）：

```bash
# 发 10 张月卡（指定应用）
curl -s -X POST http://<IP>:8080/admin/issue -H "X-Admin-Token: <TOKEN>" \
  -d '{"app_id":2,"duration_days":30,"count":10,"max_devices":1,"note":"渠道A"}'
# 封禁 / 解绑 / 续期 / 删除（支持 cards 数组批量）
curl -s -X POST http://<IP>:8080/admin/card/ban    -H "X-Admin-Token: <TOKEN>" -d '{"cards":["XXXX-..."],"banned":true}'
curl -s -X POST http://<IP>:8080/admin/card/unbind -H "X-Admin-Token: <TOKEN>" -d '{"cards":["XXXX-..."]}'
curl -s -X POST http://<IP>:8080/admin/card/extend -H "X-Admin-Token: <TOKEN>" -d '{"card":"XXXX-...","days":30}'
curl -s -X POST http://<IP>:8080/admin/card/delete -H "X-Admin-Token: <TOKEN>" -d '{"cards":["XXXX-..."]}'
# 列表（query 支持卡密/备注/设备号模糊搜索，status 支持 unused/active/banned/expired）
curl -s -X POST http://<IP>:8080/admin/cards -H "X-Admin-Token: <TOKEN>" -d '{"app_id":2,"status":"active"}'
```

## 换钥（全网失效）

泄露应急：后台「应用管理」→ 换密钥（rotate）→ 旧客户端立即 403；
把新 ks/gk 更新到你的软件重新分发即可。命令行等价：

```bash
curl -s -X POST http://<IP>:8080/admin/app/rotate -H "X-Admin-Token: <TOKEN>" -d '{"id":2}'
```
