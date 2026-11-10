# -*- coding: utf-8 -*-
"""
多应用在线卡密验证服务器 v2
================================================================
纯 Python 标准库实现, 无第三方依赖, Python 3.6+。

v2 新增:
  - 多应用隔离: apps 表, 每个系统独立卡密池, 按请求签名 ks 识别应用,
    卡密/设备/日志全按 app 隔离, 互不共通; 旧版协议零改动 (旧 APK 无感)
  - 后台账户登录: POST /login (PBKDF2 口令 + HMAC 会话 Cookie), 兼容 X-Admin-Token API
  - 批量操作: ban/unbind/delete 支持 cards 数组
  - 搜索增强: 卡密/备注/绑定设备号 模糊匹配 + 状态/应用过滤

路由:
  GET  /            管理后台单页 (admin.html)
  GET  /health      健康检查
  POST /login       后台登录 {u, p} -> 会话 Cookie
  POST /logout      退出
  GET  /me          会话检查
  POST /f           客户端卡密验证主通道
                    请求体: u\\x01b\\x01d\\x01k   响应体: g\\nr
  POST /n           netcard 兼容通道  请求体: a\\x01c\\x01d\\x01k
  POST /admin/*     管理 API (会话 Cookie 或 X-Admin-Token)
"""
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import threading
import time
from socketserver import ThreadingMixIn
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
DB_FILE = os.path.join(BASE_DIR, "data.db")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
ADMIN_HTML = os.path.join(BASE_DIR, "admin.html")


def _pbkdf2(password, salt, iters=200000):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iters).hex()


def ensure_config():
    """首次运行自动生成 config.json（随机密钥），已存在则原样使用。"""
    if os.path.isfile(CONFIG_FILE):
        return
    pwd = "xm-" + secrets.token_hex(5)
    salt = secrets.token_hex(16)
    cfg = {
        "port": 8080,
        "admin_token": secrets.token_hex(16),
        "admin_user": "admin",
        "admin_pass": "pbkdf2$200000$%s$%s" % (salt, _pbkdf2(pwd, salt)),
        "_admin_password_plain": pwd,
        "session_secret": secrets.token_hex(32),
        "ks": secrets.token_hex(16),
        "gk": secrets.token_hex(16),
        "app_secret": "",
        "build_key": secrets.token_hex(32),
        "max_devices_default": 1,
        "rate_limit_per_min": 120
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    print("=" * 62)
    print("[首次运行] 已生成 config.json（含随机密钥），请立即保存以下信息：")
    print("  管理后台账户 : %s / %s" % (cfg["admin_user"], pwd))
    print("  X-Admin-Token: %s" % cfg["admin_token"])
    print("  ks（默认应用）: %s" % cfg["ks"])
    print("  gk（默认应用）: %s" % cfg["gk"])
    print("  build_key     : %s" % cfg["build_key"])
    print("  提示: 明文密码仅本次打印（config 内只存 PBKDF2 哈希），")
    print("        _admin_password_plain 字段可自行删除。")
    print("  ks/gk 用于第一个应用（初始化时自动创建）；")
    print("  build_key 用于 /key 脚本密钥下发，可选。")
    print("=" * 62)


ensure_config()

with open(CONFIG_FILE, "r", encoding="utf-8") as _f:
    CFG = json.load(_f)

ADMIN_TOKEN = CFG["admin_token"]
ADMIN_USER = CFG.get("admin_user", "admin")
ADMIN_PASS = CFG.get("admin_pass", "")   # pbkdf2$iter$salt$hash
SESSION_SECRET = CFG.get("session_secret", ADMIN_TOKEN)
PORT = int(CFG.get("port", 8080))
MAX_DEVICES_DEFAULT = int(CFG.get("max_devices_default", 1))
RATE_LIMIT = int(CFG.get("rate_limit_per_min", 120))
COOKIE_NAME = "xmsess"
SESSION_TTL = 12 * 3600

# 卡号前缀支持任意 2~6 位字母数字（多应用系统各应用前缀不同，后台发卡自动生成）
CARD_RE = re.compile(r"[A-Z0-9]{2,6}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}", re.I)
KEY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

FAIL_RESPONSE = '{"code":10218,"message":"卡密不存在或已失效","result":null}'
NETCARD_FAIL = '{"code":-1,"message":"卡密不存在或已失效"}'
NETCARD_CLOUD_GET = '{"code":0,"message":"success","data":""}'
NETCARD_CLOUD_PUT = '{"code":0,"message":"success"}'

_write_lock = threading.Lock()

CARD_TYPES = [
    (1, "day", "日卡"),
    (7, "week", "周卡"),
    (30, "month", "月卡"),
    (90, "season", "季卡"),
    (365, "year", "年卡"),
    (0, "permanent", "永久卡"),
]


def type_names(days):
    for d, en, cn in CARD_TYPES:
        if days == d:
            return en, cn
    return ("custom", "%d天卡" % days)


def now():
    return int(time.time())


def fmt_ts(ts):
    if not ts:
        return ""
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def gen_card(prefix="XM"):
    import random
    seg = lambda: "".join(random.choice(KEY_ALPHABET) for _ in range(4))
    return "%s-%s-%s-%s" % (prefix.upper(), seg(), seg(), seg())


def hstr(key, msg):
    return hmac.new(key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def db():
    conn = sqlite3.connect(DB_FILE, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = db()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS apps(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      ks TEXT NOT NULL, gk TEXT NOT NULL, app_secret TEXT DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS cards(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      card TEXT UNIQUE NOT NULL,
      duration_days INTEGER NOT NULL DEFAULT 30,
      max_devices INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'unused',
      note TEXT DEFAULT '',
      created_at INTEGER, activated_at INTEGER, expire_at INTEGER DEFAULT 0,
      last_seen INTEGER, last_ip TEXT DEFAULT '',
      app_id INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS devices(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      card_id INTEGER NOT NULL,
      device_id TEXT NOT NULL,
      first_seen INTEGER, last_seen INTEGER, last_ip TEXT DEFAULT '',
      UNIQUE(card_id, device_id)
    );
    CREATE TABLE IF NOT EXISTS logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER, card TEXT DEFAULT '', device TEXT DEFAULT '',
      ip TEXT DEFAULT '', action TEXT DEFAULT '', ok INTEGER DEFAULT 0, detail TEXT DEFAULT '',
      app_id INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
    """)
    # 旧库迁移: 补 app_id 列
    cols = [r[1] for r in c.execute("PRAGMA table_info(cards)")]
    if "app_id" not in cols:
        c.execute("ALTER TABLE cards ADD COLUMN app_id INTEGER NOT NULL DEFAULT 1")
    cols = [r[1] for r in c.execute("PRAGMA table_info(logs)")]
    if "app_id" not in cols:
        c.execute("ALTER TABLE logs ADD COLUMN app_id INTEGER NOT NULL DEFAULT 1")
    # 首个应用: 用 config 的 ks/gk 引导 (保证旧 APK 兼容)
    if c.execute("SELECT COUNT(*) FROM apps").fetchone()[0] == 0:
        c.execute("INSERT INTO apps(name,ks,gk,app_secret,enabled,created_at) VALUES(?,?,?,?,1,?)",
                  ("默认应用", CFG["ks"], CFG["gk"], CFG.get("app_secret", ""), now()))
    c.execute("DELETE FROM logs WHERE id < (SELECT COALESCE(MAX(id),0) FROM logs) - 5000")
    conn.commit()
    conn.close()


def add_log(card, device, ip, action, ok, detail="", app_id=0):
    try:
        conn = db()
        conn.execute("INSERT INTO logs(ts,card,device,ip,action,ok,detail,app_id) VALUES(?,?,?,?,?,?,?,?)",
                     (now(), card or "", device or "", ip or "", action or "",
                      1 if ok else 0, (detail or "")[:400], app_id or 0))
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_app(app_id):
    conn = db()
    try:
        return conn.execute("SELECT * FROM apps WHERE id=?", (app_id,)).fetchone()
    finally:
        conn.close()


def get_app_by_ks(k, msg):
    """按请求签名 k 反查应用: k = HMAC(ks, msg)。找到即返回 app 行"""
    conn = db()
    try:
        for row in conn.execute("SELECT * FROM apps WHERE enabled=1"):
            if k == hstr(row["ks"], msg):
                return row
    finally:
        conn.close()
    return None


def get_card(conn, card, app_id=None):
    if app_id:
        return conn.execute("SELECT * FROM cards WHERE card=? AND app_id=?", (card, app_id)).fetchone()
    row = conn.execute("SELECT * FROM cards WHERE card=?", (card,)).fetchone()
    if row:
        return row
    return conn.execute("SELECT * FROM cards WHERE upper(card)=upper(?)", (card,)).fetchone()


def check_card(card, device_id, ip, activate, app_id=None):
    """核心校验 + 设备绑定 + 激活。返回 (card_row, devices, err)"""
    if not card:
        return None, [], "empty"
    card = card.strip().upper()
    with _write_lock:
        conn = db()
        try:
            row = get_card(conn, card, app_id)
            if not row:
                add_log(card, device_id, ip, "check", 0, "卡密不存在", app_id or 0)
                return None, [], "not_found"
            t = now()
            if row["status"] == "banned":
                add_log(card, device_id, ip, "check", 0, "已封禁", row["app_id"])
                return row, [], "banned"
            if row["status"] == "active" and row["expire_at"] and t > row["expire_at"]:
                conn.execute("UPDATE cards SET status='expired' WHERE id=?", (row["id"],))
                conn.commit()
                add_log(card, device_id, ip, "check", 0, "已过期", row["app_id"])
                return row, [], "expired"
            if row["status"] == "expired":
                add_log(card, device_id, ip, "check", 0, "已过期", row["app_id"])
                return row, [], "expired"
            devices = [dict(r) for r in conn.execute(
                "SELECT * FROM devices WHERE card_id=? ORDER BY first_seen", (row["id"],))]
            dev = None
            for d in devices:
                if d["device_id"] == (device_id or ""):
                    dev = d
                    break
            if activate:
                if row["status"] == "unused":
                    expire = (t + row["duration_days"] * 86400) if row["duration_days"] > 0 else 0
                    conn.execute("UPDATE cards SET status='active', activated_at=?, expire_at=? WHERE id=?",
                                 (t, expire, row["id"]))
                    row = get_card(conn, card, app_id)
                if dev is None and len(devices) >= row["max_devices"]:
                    add_log(card, device_id, ip, "bind", 0,
                            "设备数超限(%d/%d)" % (len(devices), row["max_devices"]), row["app_id"])
                    return row, devices, "device_limit"
                if dev is None and device_id:
                    conn.execute("INSERT INTO devices(card_id,device_id,first_seen,last_seen,last_ip) VALUES(?,?,?,?,?)",
                                 (row["id"], device_id, t, t, ip or ""))
                elif dev is not None:
                    conn.execute("UPDATE devices SET last_seen=?, last_ip=? WHERE id=?", (t, ip or "", dev["id"]))
            conn.execute("UPDATE cards SET last_seen=?, last_ip=? WHERE id=?", (t, ip or "", row["id"]))
            conn.commit()
            row = get_card(conn, card, app_id)
            if device_id:
                devices = [dict(r) for r in conn.execute(
                    "SELECT * FROM devices WHERE card_id=? ORDER BY first_seen", (row["id"],))]
            return row, devices, None
        finally:
            conn.close()


def unbind_device(card, device_id, ip, app_id=None):
    with _write_lock:
        conn = db()
        try:
            row = get_card(conn, card.strip().upper(), app_id)
            if not row:
                return False, "卡密不存在"
            if device_id:
                conn.execute("DELETE FROM devices WHERE card_id=? AND device_id=?", (row["id"], device_id))
            else:
                conn.execute("DELETE FROM devices WHERE card_id=?", (row["id"],))
            conn.commit()
            n = conn.execute("SELECT COUNT(*) FROM devices WHERE card_id=?", (row["id"],)).fetchone()[0]
            add_log(card, device_id or "(全部)", ip, "unbind", 1, "剩余绑定 %d" % n, row["app_id"])
            return True, "剩余绑定 %d 台设备" % n
        finally:
            conn.close()


# ---------------------------------------------------------------- 成功响应构造

def card_result(card_row, devices):
    days = card_row["duration_days"]
    type_en, _ = type_names(days)
    expire_at = card_row["expire_at"]
    if expire_at:
        expires = fmt_ts(expire_at)
        expires_ts = expire_at
    else:
        expires = "2099-12-31 23:59:59"
        expires_ts = 4102444799
    return {
        "card_type": type_en,
        "config": "",
        "device_id": "",
        "expires": expires,
        "expires_ts": expires_ts,
        "is_trial": False,
        "server_time": now(),
        "surplus_times": 99999 if days > 0 else 9999999,
    }


def result_qs(result):
    parts = []
    for k in sorted(result):
        v = result[k]
        if isinstance(v, bool):
            v = "true" if v else "false"
        parts.append("%s=%s" % (k, v))
    return "&".join(parts)


def make_success(card_row, devices, app_secret):
    result = card_result(card_row, devices)
    nonce = str(time.time() * 1000).split(".")[0]
    sign = hashlib.md5(("0ok" + result_qs(result) + nonce + app_secret).encode("utf-8")).hexdigest()
    inner = json.dumps({"code": 0, "message": "ok", "result": result,
                        "nonce": nonce, "sign": sign},
                       ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return ('{"header":"{Server=XM}","body":' + json.dumps(inner) +
            ',"statusCode":200,"contentType":"application/json","charset":"","statusMessage":"OK","cookie":""}')


def netcard_success(card_row, devices):
    days = card_row["duration_days"]
    _, type_cn = type_names(days)
    expire_at = card_row["expire_at"]
    end_time = fmt_ts(expire_at) if expire_at else "2099-12-31 23:59:59"
    if expire_at:
        surplus_days = max(0, (expire_at - now()) // 86400)
    else:
        surplus_days = 99999
    start_time = fmt_ts(card_row["activated_at"] or now())
    data = {
        "status": 1,
        "cardType": type_cn,
        "typeName": type_cn,
        "startTime": start_time,
        "endTime": end_time,
        "surplusDays": surplus_days,
        "isBind": 1,
        "bindCount": max(1, len(devices)),
        "maxBindCount": card_row["max_devices"],
        "deviceCount": card_row["max_devices"],
        "ext": "",
        "vip": 1,
        "level": 99,
    }
    return json.dumps({"code": 0, "message": "验证成功", "data": data},
                      ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------- 认证

def verify_password(p):
    if not ADMIN_PASS:
        return False
    try:
        _, iters, salt, want = ADMIN_PASS.split("$")
        got = hashlib.pbkdf2_hmac("sha256", (p or "").encode(), salt.encode(), int(iters)).hex()
        return hmac.compare_digest(got, want)
    except Exception:
        return False


def make_session(user):
    exp = now() + SESSION_TTL
    msg = "%s|%d" % (user, exp)
    return "%s|%d|%s" % (user, exp, hstr(SESSION_SECRET, msg))


def check_session(val):
    if not val:
        return None
    parts = val.split("|")
    if len(parts) != 3:
        return None
    user, exp, sig = parts[0], parts[1], parts[2]
    try:
        if int(exp) < now():
            return None
    except ValueError:
        return None
    if not hmac.compare_digest(hstr(SESSION_SECRET, "%s|%s" % (user, exp)), sig):
        return None
    return user


_login_fails = {}
_login_lock = threading.Lock()


def login_allowed(ip):
    with _login_lock:
        t = now()
        rec = _login_fails.get(ip)
        if rec and rec[0] >= 10 and t - rec[1] < 600:
            return False
        if rec and t - rec[1] >= 600:
            _login_fails.pop(ip, None)
        return True


def login_fail(ip):
    with _login_lock:
        rec = _login_fails.get(ip, [0, now()])
        rec = [rec[0] + 1, now()]
        _login_fails[ip] = rec


# ---------------------------------------------------------------- HTTP

_rate = {}
_rate_lock = threading.Lock()


def rate_ok(ip):
    t = int(time.time() // 60)
    with _rate_lock:
        w = _rate.get(ip)
        if not w or w[0] != t:
            _rate[ip] = [t, 1]
            if len(_rate) > 4096:
                _rate.clear()
            return True
        w[1] += 1
        return w[1] <= RATE_LIMIT


class Handler(BaseHTTPRequestHandler):
    server_version = "XMCard/2.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", cookie=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(data)
        except Exception:
            pass

    def _json(self, obj, code=200, cookie=None):
        self._send(code, json.dumps(obj, ensure_ascii=False), cookie=cookie)

    def _read_body(self, limit=65536):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > limit:
            return b""
        return self.rfile.read(n)

    def _ip(self):
        return self.client_address[0] if self.client_address else ""

    def _session_user(self):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith(COOKIE_NAME + "="):
                return check_session(part[len(COOKIE_NAME) + 1:])
        return None

    def _admin_ok(self):
        if self._session_user():
            return True
        tok = self.headers.get("X-Admin-Token") or ""
        return hmac.compare_digest(tok, ADMIN_TOKEN)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/health":
            return self._send(200, "ok", "text/plain")
        if path == "/me":
            u = self._session_user()
            if u:
                return self._json({"ok": True, "user": u})
            return self._json({"ok": False}, 401)
        if path == "/":
            try:
                with open(ADMIN_HTML, "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            except Exception:
                return self._send(404, "admin.html missing", "text/plain")
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        ip = self._ip()
        path = self.path.split("?")[0]
        if path in ("/login", "/logout"):
            return self.handle_auth(path, ip)
        if path in ("/f", "/n", "/key"):
            if not rate_ok(ip):
                return self._send(429, "too many", "text/plain")
            return self.handle_client_channel(path, ip)
        if path.startswith("/admin/"):
            if not self._admin_ok():
                return self._json({"error": "unauthorized"}, 401)
            return self.handle_admin(path, ip)
        return self._json({"error": "not found"}, 404)

    # ---- 登录
    def handle_auth(self, path, ip):
        body = {}
        raw = self._read_body()
        if raw:
            try:
                body = json.loads(raw.decode("utf-8"))
            except Exception:
                return self._json({"error": "bad json"}, 400)
        if path == "/logout":
            return self._json({"ok": True},
                              cookie="%s=; Path=/; HttpOnly; Max-Age=0" % COOKIE_NAME)
        if not login_allowed(ip):
            return self._json({"error": "尝试过多, 请10分钟后再试"}, 429)
        if body.get("u") == ADMIN_USER and verify_password(body.get("p")):
            with _login_lock:
                _login_fails.pop(ip, None)
            ck = "%s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d" % (
                COOKIE_NAME, make_session(ADMIN_USER), SESSION_TTL)
            add_log("", "", ip, "login", 1, ADMIN_USER)
            return self._json({"ok": True}, cookie=ck)
        login_fail(ip)
        add_log(body.get("u") or "", "", ip, "login", 0, "口令错误")
        return self._json({"error": "用户名或密码错误"}, 401)

    # ---- 客户端通道
    def handle_client_channel(self, path, ip):
        raw = self._read_body()
        if not raw:
            return self._send(400, "empty body", "text/plain")
        try:
            text = raw.decode("utf-8", "replace")
            parts = text.split("\x01")
            if path == "/key":
                c, d, k = (parts + ["", "", ""])[:3]
                msg = c + "\x01" + d
                app = get_app_by_ks(k, msg)
                if app is None:
                    return self._send(403, "bad signature", "text/plain")
                row, devices, err = check_card(c, d, ip, activate=True, app_id=app["id"])
                if err:
                    r = '{"error":"卡密无效"}'
                else:
                    bk = CFG.get("build_key") or ""
                    r = (json.dumps({"key": bk, "expires": fmt_ts(row["expire_at"]) or "永久"})
                         if bk else '{"error":"未配置脚本密钥"}')
            elif path == "/f":
                u, b, d, k = (parts + ["", "", "", ""])[:4]
                msg = u + "\x01" + b + "\x01" + d
                app = get_app_by_ks(k, msg)
                if app is None:
                    return self._send(403, "bad signature", "text/plain")
                r = self.forward_verify(u, b, d, ip, app)
            else:
                a, c, d, k = (parts + ["", "", "", ""])[:4]
                msg = a + "\x01" + c + "\x01" + d
                app = get_app_by_ks(k, msg)
                if app is None:
                    return self._send(403, "bad signature", "text/plain")
                r = self.forward_netcard(a, c, d, ip, app)
        except Exception as e:
            r = FAIL_RESPONSE if path == "/f" else NETCARD_FAIL
            app = get_app(1)  # 兜底: 用默认应用门禁签名失败串(内容本就是固定失败)
            add_log("", "", ip, path, 0, "exception: %s" % e)
        gate = hstr(app["gk"] if app else CFG["gk"], r)
        return self._send(200, gate + "\n" + r, "text/plain")

    def forward_verify(self, u, b, d, ip, app):
        blob = (u or "") + "\n" + (b or "")
        cards = CARD_RE.findall(blob)
        if not cards:
            add_log("", d, ip, "verify", 0, "未发现卡号", app["id"])
            return FAIL_RESPONSE
        card = cards[0].upper()
        row, devices, err = check_card(card, d, ip, activate=True, app_id=app["id"])
        if err:
            return FAIL_RESPONSE
        add_log(card, d, ip, "verify", 1, "%s 到期 %s" % (
            type_names(row["duration_days"])[1], fmt_ts(row["expire_at"]) or "永久"), app["id"])
        return make_success(row, devices, app["app_secret"] or CFG.get("app_secret", ""))

    def forward_netcard(self, a, c, d, ip, app):
        a = (a or "").lower()
        if a == "unbind":
            row, devices, err = check_card(c, d, ip, activate=False, app_id=app["id"])
            if err:
                return NETCARD_FAIL
            unbind_device(c, d, ip, app_id=app["id"])
            row2, devices2, err2 = check_card(c, "", ip, activate=False, app_id=app["id"])
            return netcard_success(row2 or row, devices2 or devices)
        row, devices, err = check_card(c, d, ip, activate=True, app_id=app["id"])
        if err:
            return NETCARD_FAIL
        add_log((c or "").upper(), d, ip, "netcard." + a, 1, "", app["id"])
        return netcard_success(row, devices)

    # ---- 管理
    def handle_admin(self, path, ip):
        body = {}
        raw = self._read_body()
        if raw:
            try:
                body = json.loads(raw.decode("utf-8"))
            except Exception:
                return self._json({"error": "bad json"}, 400)

        if path == "/admin/stat":
            app_id = body.get("app_id")
            conn = db()
            if app_id:
                total = conn.execute("SELECT COUNT(*) FROM cards WHERE app_id=?", (app_id,)).fetchone()[0]
                by = {r[0]: r[1] for r in conn.execute(
                    "SELECT status, COUNT(*) FROM cards WHERE app_id=? GROUP BY status", (app_id,))}
                devs = conn.execute("SELECT COUNT(*) FROM devices d JOIN cards c ON d.card_id=c.id"
                                    " WHERE c.app_id=?", (app_id,)).fetchone()[0]
                today = conn.execute("SELECT COUNT(*) FROM logs WHERE ts>=? AND action='verify' AND ok=1 AND app_id=?",
                                     (now() - 86400, app_id)).fetchone()[0]
            else:
                total = conn.execute("SELECT COUNT(*) FROM cards").fetchone()[0]
                by = {r[0]: r[1] for r in conn.execute("SELECT status, COUNT(*) FROM cards GROUP BY status")}
                devs = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
                today = conn.execute("SELECT COUNT(*) FROM logs WHERE ts>=? AND action='verify' AND ok=1",
                                     (now() - 86400,)).fetchone()[0]
            conn.close()
            return self._json({"total": total, "by_status": by, "devices": devs, "logins_24h": today})

        if path == "/admin/apps":
            conn = db()
            rows = conn.execute("SELECT * FROM apps ORDER BY id").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["cards"] = conn.execute("SELECT COUNT(*) FROM cards WHERE app_id=?", (r["id"],)).fetchone()[0]
                d["active"] = conn.execute("SELECT COUNT(*) FROM cards WHERE app_id=? AND status='active'",
                                           (r["id"],)).fetchone()[0]
                d["created_at_s"] = fmt_ts(r["created_at"])
                out.append(d)
            conn.close()
            return self._json({"apps": out})

        if path == "/admin/app/create":
            name = (body.get("name") or "").strip()[:30]
            if not name:
                return self._json({"error": "应用名不能为空"}, 400)
            conn = db()
            try:
                conn.execute("INSERT INTO apps(name,ks,gk,app_secret,enabled,created_at) VALUES(?,?,?,?,1,?)",
                             (name, secrets.token_hex(16), secrets.token_hex(16),
                              (body.get("app_secret") or "")[:128], now()))
                conn.commit()
                row = conn.execute("SELECT * FROM apps WHERE name=?", (name,)).fetchone()
                add_log("", "", ip, "app.create", 1, name)
                return self._json({"ok": True, "app": dict(row)})
            except sqlite3.IntegrityError:
                return self._json({"error": "应用名已存在"}, 400)
            finally:
                conn.close()

        if path == "/admin/app/update":
            app = get_app(body.get("id"))
            if not app:
                return self._json({"error": "应用不存在"}, 404)
            conn = db()
            name = (body.get("name") or app["name"]).strip()[:30]
            enabled = 1 if body.get("enabled", app["enabled"]) else 0
            app_secret = (body.get("app_secret") if body.get("app_secret") is not None
                          else app["app_secret"])[:128]
            conn.execute("UPDATE apps SET name=?, enabled=?, app_secret=? WHERE id=?",
                         (name, enabled, app_secret, app["id"]))
            conn.commit()
            conn.close()
            add_log("", "", ip, "app.update", 1, "%s enabled=%d" % (name, enabled))
            return self._json({"ok": True})

        if path == "/admin/app/rotate":
            app = get_app(body.get("id"))
            if not app:
                return self._json({"error": "应用不存在"}, 404)
            conn = db()
            new_ks, new_gk = secrets.token_hex(16), secrets.token_hex(16)
            conn.execute("UPDATE apps SET ks=?, gk=? WHERE id=?", (new_ks, new_gk, app["id"]))
            conn.commit()
            conn.close()
            add_log("", "", ip, "app.rotate", 1, app["name"])
            return self._json({"ok": True, "ks": new_ks, "gk": new_gk,
                               "warn": "旧 APK 打包内嵌的 ks/gk 已作废, 需用新密钥重新打包"})

        if path == "/admin/cards":
            q = (body.get("query") or "").strip()
            st = (body.get("status") or "").strip()
            app_id = body.get("app_id")
            cond, params = [], []
            if q:
                cond.append("(card LIKE ? OR note LIKE ? OR id IN "
                            "(SELECT card_id FROM devices WHERE device_id LIKE ?))")
                params += ["%" + q + "%", "%" + q + "%", "%" + q + "%"]
            if st in ("unused", "active", "banned", "expired"):
                cond.append("status=?")
                params.append(st)
            if app_id:
                cond.append("app_id=?")
                params.append(app_id)
            sql = "SELECT * FROM cards" + (" WHERE " + " AND ".join(cond) if cond else "")
            conn = db()
            rows = conn.execute(sql + " ORDER BY id DESC LIMIT 500", params).fetchall()
            apps = {r["id"]: r["name"] for r in conn.execute("SELECT id,name FROM apps")}
            out = []
            for r in rows:
                dv = [dict(x) for x in conn.execute(
                    "SELECT device_id, first_seen, last_seen, last_ip FROM devices WHERE card_id=? ORDER BY first_seen",
                    (r["id"],))]
                d = dict(r)
                d["created_at_s"] = fmt_ts(d["created_at"])
                d["activated_at_s"] = fmt_ts(d["activated_at"])
                d["expire_at_s"] = fmt_ts(d["expire_at"]) if d["expire_at"] else "永久"
                d["last_seen_s"] = fmt_ts(d["last_seen"])
                d["devices"] = dv
                d["type_cn"] = type_names(d["duration_days"])[1]
                d["app_name"] = apps.get(d["app_id"], "?")
                out.append(d)
            conn.close()
            return self._json({"cards": out})

        if path == "/admin/issue":
            count = min(int(body.get("count", 1)), 500)
            days = int(body.get("duration_days", 30))
            maxd = int(body.get("max_devices", MAX_DEVICES_DEFAULT))
            note = (body.get("note") or "")[:100]
            prefix = re.sub(r"[^A-Za-z0-9]", "", body.get("prefix") or "XM")[:6].upper() or "XM"
            app_id = body.get("app_id") or 1
            if not get_app(app_id):
                return self._json({"error": "应用不存在"}, 404)
            made = []
            conn = db()
            t = now()
            with _write_lock:
                while len(made) < count:
                    key = gen_card(prefix)
                    try:
                        conn.execute(
                            "INSERT INTO cards(card,duration_days,max_devices,status,note,created_at,expire_at,app_id)"
                            " VALUES(?,?,?,'unused',?,?,0,?)",
                            (key, days, maxd, note, t, app_id))
                        conn.commit()
                        made.append(key)
                    except sqlite3.IntegrityError:
                        continue
            conn.close()
            add_log("", "", ip, "issue", 1, "[%s] 发放 %d 张 %s" % (
                get_app(app_id)["name"], count, type_names(days)[1]), app_id)
            return self._json({"cards": made, "type_cn": type_names(days)[1]})

        if path == "/admin/card/ban":
            cards = body.get("cards") or ([body.get("card")] if body.get("card") else [])
            banned = bool(body.get("banned", True))
            ok, miss = 0, []
            with _write_lock:
                conn = db()
                try:
                    for card in cards:
                        row = get_card(conn, (card or "").strip().upper())
                        if not row:
                            miss.append(card)
                            continue
                        conn.execute("UPDATE cards SET status=? WHERE id=?",
                                     ("banned" if banned else "unused", row["id"]))
                        ok += 1
                    conn.commit()
                finally:
                    conn.close()
            add_log(",".join(cards[:3]) + ("..." if len(cards) > 3 else ""), "", ip,
                    "ban" if banned else "unban", 1, "%d 张" % ok)
            return self._json({"ok": ok, "missing": miss})

        if path == "/admin/card/unbind":
            cards = body.get("cards") or ([body.get("card")] if body.get("card") else [])
            device = (body.get("device_id") or "").strip()
            ok, miss = 0, []
            for card in cards:
                r, msg = unbind_device(card, device, ip)
                if r:
                    ok += 1
                else:
                    miss.append(card)
            return self._json({"ok": ok, "missing": miss})

        if path == "/admin/card/delete":
            cards = body.get("cards") or ([body.get("card")] if body.get("card") else [])
            ok, miss = 0, []
            with _write_lock:
                conn = db()
                try:
                    for card in cards:
                        row = get_card(conn, (card or "").strip().upper())
                        if not row:
                            miss.append(card)
                            continue
                        conn.execute("DELETE FROM devices WHERE card_id=?", (row["id"],))
                        conn.execute("DELETE FROM cards WHERE id=?", (row["id"],))
                        ok += 1
                    conn.commit()
                finally:
                    conn.close()
            add_log(",".join(cards[:3]) + ("..." if len(cards) > 3 else ""), "", ip,
                    "delete", 1, "删除 %d 张" % ok)
            return self._json({"ok": ok, "missing": miss})

        if path == "/admin/card/extend":
            card = (body.get("card") or "").strip().upper()
            days = int(body.get("days", 0))
            conn = db()
            row = get_card(conn, card)
            if not row:
                conn.close()
                return self._json({"error": "卡密不存在"}, 404)
            base = row["expire_at"] if (row["expire_at"] and row["expire_at"] > now()) else now()
            if row["duration_days"] == 0 and not body.get("force"):
                conn.close()
                return self._json({"error": "永久卡无需续期"}, 400)
            new_expire = base + days * 86400
            conn.execute("UPDATE cards SET expire_at=?, status=CASE WHEN status='expired' THEN 'active' ELSE status END"
                         " WHERE id=?", (new_expire, row["id"]))
            conn.commit()
            conn.close()
            add_log(card, "", ip, "extend", 1, "+%dd -> %s" % (days, fmt_ts(new_expire)), row["app_id"])
            return self._json({"ok": True, "expire_at": fmt_ts(new_expire)})

        if path == "/admin/card/note":
            card = (body.get("card") or "").strip().upper()
            note = (body.get("note") or "")[:100]
            conn = db()
            row = get_card(conn, card)
            if not row:
                conn.close()
                return self._json({"error": "卡密不存在"}, 404)
            conn.execute("UPDATE cards SET note=? WHERE id=?", (note, row["id"]))
            conn.commit()
            conn.close()
            return self._json({"ok": True})

        if path == "/admin/logs":
            limit = min(int(body.get("limit", 200)), 1000)
            app_id = body.get("app_id")
            conn = db()
            if app_id:
                rows = conn.execute("SELECT * FROM logs WHERE app_id=? ORDER BY id DESC LIMIT ?",
                                    (app_id, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            conn.close()
            out = [dict(r) for r in rows]
            for r in out:
                r["ts_s"] = fmt_ts(r["ts"])
            return self._json({"logs": out})

        return self._json({"error": "unknown admin endpoint"}, 404)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def backup_db():
    if not os.path.isfile(DB_FILE):
        return
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        today = datetime.datetime.now().strftime("%Y%m%d")
        dst = os.path.join(BACKUP_DIR, "data-%s.db" % today)
        if not os.path.isfile(dst):
            shutil.copy2(DB_FILE, dst)
            keep = sorted(os.listdir(BACKUP_DIR))[:-7]
            for old in keep:
                os.remove(os.path.join(BACKUP_DIR, old))
    except Exception:
        pass


def main():
    init_db()
    backup_db()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("[XMCard v2] listening on 0.0.0.0:%d  db=%s" % (PORT, DB_FILE))
    srv.serve_forever()


if __name__ == "__main__":
    main()
