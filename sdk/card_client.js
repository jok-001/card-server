/**
 * Card Server 客户端参考实现（JavaScript / AutoJs6 · Rhino 兼容）
 * ================================================================
 * 复制本文件到你的 AutoJs6 项目即可使用。
 * 已处理 AutoJs6 的坑：http.request 不支持字符串 body → 用 HttpURLConnection 直连。
 *
 * 用法：
 *   var card = require("./card_client.js");
 *   card.init("http://<服务器IP>:8080", "<应用ks>", "<应用gk>");
 *   var r = card.verify("ABCD-1234-ABCD-1234");
 *   if (!r.ok) { toast(r.message); exit(); }
 *   // 可选：心跳（每 15 分钟复验，失败自动重登一次，仍失败回调）
 *   card.startHeartbeat("ABCD-1234-ABCD-1234", function (msg) { exit(); });
 */

var CONF = {
    SERVER: "",
    KS: "",
    GK: "",
    GRACE_MS: 48 * 3600 * 1000,
    HEARTBEAT_MS: 15 * 60 * 1000
};
var SEP = "\u0001";
var loginInfo = null;

function init(server, ks, gk) {
    CONF.SERVER = server.replace(/\/+$/, "");
    CONF.KS = ks;
    CONF.GK = gk;
}

function toHex(a) {
    var s = "";
    for (var i = 0; i < a.length; i++) {
        var b = a[i] & 0xff;
        s += (b < 16 ? "0" : "") + b.toString(16);
    }
    return s;
}

function hmac256(key, msg) {
    var mac = javax.crypto.Mac.getInstance("HmacSHA256");
    mac.init(new javax.crypto.spec.SecretKeySpec(
        new java.lang.String(key).getBytes("UTF-8"), "HmacSHA256"));
    return toHex(mac.doFinal(new java.lang.String(msg).getBytes("UTF-8")));
}

function postRaw(url, payloadStr) {
    var conn = new java.net.URL(url).openConnection();
    conn.setRequestMethod("POST");
    conn.setDoOutput(true);
    conn.setConnectTimeout(8000);
    conn.setReadTimeout(8000);
    conn.setRequestProperty("Content-Type", "application/octet-stream");
    var out = conn.getOutputStream();
    out.write(new java.lang.String(payloadStr).getBytes("UTF-8"));
    out.close();
    var code = conn.getResponseCode();
    var is = code === 200 ? conn.getInputStream() : conn.getErrorStream();
    var baos = new java.io.ByteArrayOutputStream();
    var buf = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, 4096);
    var n;
    while ((n = is.read(buf)) > 0) baos.write(buf, 0, n);
    is.close();
    return { code: code, body: new java.lang.String(baos.toByteArray(), "UTF-8") };
}

function deviceId() {
    try {
        return device.getAndroidId() || "unknown";
    } catch (e) {
        return "unknown";
    }
}

/* ---- 断网宽限缓存（XOR 混淆存私有目录） ---- */
function cachePath() {
    return (typeof files !== "undefined" && files.cwd() ? files.cwd() : ".") + "/.card_grant.dat";
}
function saveGrant(body) {
    try {
        var payload = body + "\u0001" + Date.now();
        var bytes = new java.lang.String(payload).getBytes("UTF-8");
        var kb = new java.lang.String(CONF.GK).getBytes("UTF-8");
        for (var i = 0; i < bytes.length; i++) {
            bytes[i] = (bytes[i] ^ kb[i % kb.length]) & 0xff;
        }
        var jsBytes = [];
        for (var j = 0; j < bytes.length; j++) jsBytes.push(bytes[j] & 0xff);
        files.writeBytes(cachePath(), jsBytes);
    } catch (e) { /* 宽限缓存失败不影响主流程 */ }
}
function loadGrant() {
    try {
        if (!files.exists(cachePath())) return null;
        var jsBytes = files.readBytes(cachePath());
        var bytes = java.lang.reflect.Array.newInstance(java.lang.Byte.TYPE, jsBytes.length);
        var kb = new java.lang.String(CONF.GK).getBytes("UTF-8");
        for (var i = 0; i < jsBytes.length; i++) {
            bytes[i] = new java.lang.Byte((jsBytes[i] ^ kb[i % kb.length]) & 0xff);
        }
        var payload = new java.lang.String(bytes, "UTF-8");
        var idx = payload.lastIndexOf("\u0001");
        if (idx < 0) return null;
        if (Date.now() - Number(payload.substring(idx + 1)) > CONF.GRACE_MS) return null;
        return payload.substring(0, idx);
    } catch (e) {
        return null;
    }
}
function clearGrant() {
    try { files.remove(cachePath()); } catch (e) { /* ignore */ }
}

/* ---- 解析响应（双层 JSON） ---- */
function parseResp(resp, offline) {
    var outer = JSON.parse(resp);
    var inner = JSON.parse(outer.body || "{}");
    if (inner.code !== 0) {
        return { ok: false, message: inner.message || "未知失败" };
    }
    var res = inner.result || {};
    return { ok: true, message: offline ? "离线宽限" : "ok", expires: res.expires || "", info: res };
}

/* ---- 主入口：验证卡密 ---- */
function verify(card) {
    var url = CONF.SERVER + "/f";
    var body = "card=" + card;
    var msg = url + SEP + body + SEP + deviceId();
    var payload = msg + SEP + hmac256(CONF.KS, msg);
    var resp;
    try {
        resp = postRaw(url, payload);
    } catch (e) {
        var cached = loadGrant();
        if (cached) return parseResp(cached, true);
        return { ok: false, message: "无法连接验证服务器，且无离线宽限" };
    }
    if (resp.code !== 200) {
        return { ok: false, message: "服务异常 HTTP " + resp.code };
    }
    var idx = resp.body.indexOf("\n");
    var gate = resp.body.substring(0, idx);
    var r = resp.body.substring(idx + 1);
    if (hmac256(CONF.GK, r) !== gate) {
        return { ok: false, message: "响应校验失败（门禁不符）" };
    }
    if (r.indexOf("10218") >= 0) {
        clearGrant();
        return { ok: false, message: "卡密不存在或已失效" };
    }
    saveGrant(r);
    return parseResp(r, false);
}

/* ---- 心跳 ---- */
function startHeartbeat(card, onFail) {
    threads.start(function () {
        while (true) {
            sleep(CONF.HEARTBEAT_MS);
            var r = verify(card);
            if (!r.ok) {
                sleep(3000);
                var r2 = verify(card);
                if (!r2.ok) {
                    if (onFail) onFail(r2.message);
                    return;
                }
            }
        }
    });
}

/* ---- 可选：脚本解密密钥下发 ---- */
function fetchBuildKey(card) {
    var url = CONF.SERVER + "/key";
    var msg = card + SEP + deviceId();
    var payload = msg + SEP + hmac256(CONF.KS, msg);
    var resp = postRaw(url, payload);
    if (resp.code !== 200) return null;
    var idx = resp.body.indexOf("\n");
    var gate = resp.body.substring(0, idx);
    var r = resp.body.substring(idx + 1);
    if (hmac256(CONF.GK, r) !== gate) return null;
    return JSON.parse(r).key || null;
}

module.exports = {
    init: init,
    verify: verify,
    startHeartbeat: startHeartbeat,
    fetchBuildKey: fetchBuildKey
};
