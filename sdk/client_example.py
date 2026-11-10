# -*- coding: utf-8 -*-
"""
Card Server 客户端参考实现（Python）
====================================
依赖：仅 Python 标准库。复制本文件到你的项目即可使用。

用法：
    from card_client import CardClient
    cc = CardClient(server="http://<服务器IP>:8080",
                    ks="<应用ks>", gk="<应用gk>")
    r = cc.verify("ABCD-1234-ABCD-1234")
    if r.ok:
        print("验证通过，到期：", r.expires)
    else:
        print("失败：", r.message)
"""
import hashlib
import hmac
import json
import os
import time
import urllib.request

SEP = "\x01"


class VerifyResult(object):
    def __init__(self, ok, message="", expires="", info=None):
        self.ok = ok
        self.message = message
        self.expires = expires
        self.info = info or {}

    def __repr__(self):
        return "VerifyResult(ok=%s, message=%r, expires=%r)" % (self.ok, self.message, self.expires)


def _hmac_hex(key, msg):
    return hmac.new(key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def _post_raw(url, payload):
    req = urllib.request.Request(url, data=payload.encode("utf-8"),
                                 headers={"Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8")


class CardClient(object):
    def __init__(self, server, ks, gk, device_id="", grace_hours=48,
                 cache_file=".card_grant.dat"):
        self.server = server.rstrip("/")
        self.ks = ks
        self.gk = gk
        self.device_id = device_id or self._default_device_id()
        self.grace_hours = grace_hours
        self.cache_file = cache_file

    def _default_device_id(self):
        import uuid
        return uuid.uuid1().hex[:16].upper()

    # ---- 低层：签名请求 + 门禁验签 ----
    def _call(self, path, parts):
        url = self.server + path
        msg = SEP.join(parts)
        sign = _hmac_hex(self.ks, msg)
        resp = _post_raw(url, msg + SEP + sign)
        idx = resp.index("\n")
        gate, body = resp[:idx], resp[idx + 1:]
        if _hmac_hex(self.gk, body) != gate:
            raise IOError("响应门禁校验失败（响应被篡改或 gk 不匹配）")
        return body

    # ---- 断网宽限缓存 ----
    def _save_grant(self, body):
        blob = json.dumps({"body": body, "ts": time.time()}).encode("utf-8")
        key = self.gk.encode("utf-8")
        with open(self.cache_file, "wb") as f:
            f.write(bytes(b ^ key[i % len(key)] for i, b in enumerate(blob)))

    def _load_grant(self):
        try:
            with open(self.cache_file, "rb") as f:
                blob = f.read()
            key = self.gk.encode("utf-8")
            blob = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))
            obj = json.loads(blob.decode("utf-8"))
            if time.time() - obj["ts"] > self.grace_hours * 3600:
                return None
            return obj["body"]
        except Exception:
            return None

    def _clear_grant(self):
        try:
            os.remove(self.cache_file)
        except OSError:
            pass

    # ---- 主入口：验证卡密 ----
    def verify(self, card):
        url = self.server + "/f"
        body = "card=" + card
        parts = [url, body, self.device_id]
        try:
            resp = self._call("/f", parts)
        except IOError as e:
            if "门禁" in str(e):
                raise
            cached = self._load_grant()
            if cached:
                return self._parse(cached, offline=True)
            return VerifyResult(False, "无法连接验证服务器，且无离线宽限")
        if "10218" in resp:
            self._clear_grant()
            return VerifyResult(False, "卡密不存在或已失效")
        self._save_grant(resp)
        return self._parse(resp)

    def _parse(self, resp, offline=False):
        """resp 是双层 JSON：外层包装 + 内层 {code,result:{expires,...}}"""
        outer = json.loads(resp)
        inner = json.loads(outer.get("body", "{}"))
        if inner.get("code") != 0:
            return VerifyResult(False, inner.get("message", "未知失败"))
        res = inner.get("result", {})
        return VerifyResult(True,
                            "离线宽限" if offline else "ok",
                            expires=res.get("expires", ""),
                            info=res)

    # ---- 心跳（登录成功后定期调用）----
    def start_heartbeat(self, card, interval_sec=900, on_fail=None):
        import threading

        def loop():
            while True:
                time.sleep(interval_sec)
                r = self.verify(card)
                if not r.ok:
                    r2 = self.verify(card)
                    if not r2.ok:
                        if on_fail:
                            on_fail(r2.message)
                        return

        t = threading.Thread(target=loop)
        t.daemon = True
        t.start()
        return t

    # ---- 可选：脚本解密密钥下发 ----
    def fetch_build_key(self, card):
        body = self._call("/key", [card, self.device_id])
        obj = json.loads(body)
        return obj.get("key")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("用法: python client_example.py <server> <ks> <gk> <card>")
        sys.exit(1)
    cc = CardClient(sys.argv[1], sys.argv[2], sys.argv[3])
    print(cc.verify(sys.argv[4]))
