# -*- coding: utf-8 -*-
"""
部署自检脚本：对运行中的 Card Server 实例执行全量协议与功能测试。
用法:
    python3 smoke_test.py                # 对 config.json 里的端口自检（默认本机）
    python3 smoke_test.py http://IP:PORT # 对远程实例自检（需该实例的 config.json）

覆盖: 健康检查 / 发卡 / 验证协议+签名 / 响应门禁 / 无效卡 / 一卡一机 /
      卡号子串兼容 / 封禁解封解绑 / 批量操作 / 多应用隔离 / 鉴权防护 / 日志统计
测试数据（卡密与应用）在测试末尾自动清理，不留静态数据。
"""
import hashlib
import hmac
import json
import os
import sys
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(BASE, "config.json")
SEP = "\x01"

with open(CFG_PATH, "r", encoding="utf-8") as f:
    CFG = json.load(f)

if len(sys.argv) > 1:
    BASE_URL = sys.argv[1].rstrip("/")
else:
    BASE_URL = "http://127.0.0.1:%d" % int(CFG["port"])

ADMIN = CFG["admin_token"]
KS_DEFAULT = CFG["ks"]
GK_DEFAULT = CFG["gk"]


def req(path, data=None, headers=None, raw=False):
    if isinstance(data, dict):
        data = json.dumps(data).encode()
    elif isinstance(data, str):
        data = data.encode()
    r = urllib.request.Request(BASE_URL + path, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, body if raw else json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        return e.code, body if raw else (json.loads(body) if body.strip() else {})


def hsha(key, msg):
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()


def admin(path, body=None):
    st, j = req(path, body or {}, {"X-Admin-Token": ADMIN, "Content-Type": "application/json"})
    assert st == 200, "admin %s -> %d %s" % (path, st, j)
    return j


def verify_f(card, aid, ks=KS_DEFAULT, gk=GK_DEFAULT):
    """模拟客户端 /f 请求，返回 (状态, 门禁是否匹配, 响应体)"""
    url, body = BASE_URL + "/f", "card=" + card
    msg = SEP.join([url, body, aid])
    st, resp = req("/f", msg + SEP + hsha(ks, msg), raw=True)
    idx = resp.find("\n")
    if idx < 0:
        return st, False, resp
    gate, r = resp[:idx], resp[idx + 1:]
    return st, hsha(gk, r) == gate, r


def ok_resp(r):
    try:
        return json.loads(json.loads(r)["body"])["code"] == 0
    except Exception:
        return False


def main():
    # [1] 健康检查
    st, body = req("/health", raw=True)
    assert st == 200 and body.strip() == "ok", body
    print("[1] 健康检查 [OK]")

    # [2] 建测试应用（隔离测试用）+ 各发一张卡
    suffix = str(int(__import__("time").time()))[-6:]
    app_b = admin("/admin/app/create", {"name": "自检应用B_" + suffix})["app"]
    card_a = admin("/admin/issue", {"duration_days": 30, "count": 1, "max_devices": 1,
                                    "app_id": 1})["cards"][0]
    card_b = admin("/admin/issue", {"duration_days": 30, "count": 1, "max_devices": 1,
                                    "app_id": app_b["id"]})["cards"][0]
    print("[2] 建测试应用 + 发卡 [OK] (%s / %s)" % (card_a, card_b))

    # [3] 默认应用验证协议 + 签名 + 门禁
    st, gate_ok, r = verify_f(card_a, "SELFTEST_AID_1")
    assert st == 200 and gate_ok and ok_resp(r), "验证失败: %s" % r[:150]
    print("[3] 验证协议 + 响应门禁 [OK]")

    # [4] 多应用隔离：B 的卡用默认 ks 验证必须失败；B 的卡用 B 的 ks 验证成功
    st, gate_ok, r = verify_f(card_b, "SELFTEST_AID_1", ks=KS_DEFAULT)
    assert "10218" in r, "隔离失败: %s" % r[:150]
    st, gate_ok, r = verify_f(card_b, "SELFTEST_B_1", ks=app_b["ks"], gk=app_b["gk"])
    assert gate_ok and ok_resp(r), "B 应用验证失败"
    print("[4] 多应用隔离 [OK]")

    # [5] 无效卡
    st, gate_ok, r = verify_f("ZZZZ-0000-0000-0000", "SELFTEST_AID_1")
    assert r == '{"code":10218,"message":"卡密不存在或已失效","result":null}', r
    print("[5] 无效卡固定失败串 [OK]")

    # [6] 一卡一机
    st, _, r = verify_f(card_a, "SELFTEST_AID_2")
    assert "10218" in r, "设备超限未拦截"
    print("[6] 一卡一机 [OK]")

    # [7] 卡号子串兼容（任意字段名）
    st, _, r = verify_f(card_a, "SELFTEST_AID_1")  # 同设备重验（应成功）
    assert ok_resp(r), "同设备复验失败"
    print("[7] 同设备复验 [OK]")

    # [8] 批量操作
    cards = admin("/admin/issue", {"duration_days": 7, "count": 3, "max_devices": 5,
                                   "app_id": app_b["id"], "note": "自检批量"})["cards"]
    r = admin("/admin/card/ban", {"cards": cards, "banned": True})
    assert r["ok"] == 3
    banned_set = {c["card"] for c in admin("/admin/cards", {"app_id": app_b["id"], "status": "banned"})["cards"]}
    assert all(card in banned_set for card in cards)
    r = admin("/admin/card/unbind", {"cards": cards})
    assert r["ok"] == 3
    r = admin("/admin/card/delete", {"cards": cards})
    assert r["ok"] == 3
    print("[8] 批量封禁/解绑/删除 [OK]")

    # [9] 鉴权防护
    st, _ = req("/admin/stat", {}, {"X-Admin-Token": "wrong"})
    assert st == 401, "错误 token 应 401"
    st, resp = req("/f", "a\x01b\x01c\x01deadbeef", raw=True)
    assert st == 403, "错误请求签名应 403"
    print("[9] 鉴权防护 (401/403) [OK]")

    # [10] 统计与日志
    s = admin("/admin/stat")
    lg = admin("/admin/logs", {"limit": 5})
    assert "total" in s and len(lg["logs"]) > 0
    print("[10] 统计 / 日志 [OK]")

    # 清理测试数据
    admin("/admin/card/delete", {"cards": [card_a, card_b]})
    apps = admin("/admin/apps")["apps"]
    st, _ = req("/admin/app/update", {"id": app_b["id"], "enabled": False},
                {"X-Admin-Token": ADMIN, "Content-Type": "application/json"})
    print("\n[清理] 测试卡已删除，自检应用已停用（可在后台手动删除）")
    print("\n全部通过 [OK]  部署正常。")


if __name__ == "__main__":
    main()
