# @interval: 12h
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
星链 VPN 自动抓取（沙盒版）—— 国内+国际节点，输出 VLESS/Hy2 订阅
"""
import base64, json, os, ssl, sys, urllib.parse, urllib.request

API = "https://apis.nexgentechhub.net/api/v1/auth/get_configs"
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiI4ODIxODg3MTEwNjI2NjcyNjQiLCJleHAiOjQzODAxMzkwNzgsInJvbGUiOjF9.Uq2mImzv8fSCuMbBatPFrMX4XaLGC-_K8eWRsuzfsrY"
DEVICE = "9a6d8d2a-5f70-4f14-ad10-8fc94b879570"
KEY = b"mateforce-cn-jiasuqi-length-keys"
OUT_FILE = "safevpn_sub.txt"
OUT_PATH = OUT_FILE # 沙盒环境下直接输出到当前目录

# ---------- AES 解密 ----------
try:
    from Crypto.Cipher import AES
    def decrypt(key, iv, data):
        return AES.new(key, AES.MODE_CBC, iv).decrypt(data)
except ImportError:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    def decrypt(key, iv, data):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return cipher.update(data) + cipher.finalize()

def unpad(b):
    p = b[-1]
    if not (1 <= p <= 16) or b[-p:] != bytes([p]) * p:
        raise ValueError("填充错误")
    return b[:-p]

# ---------- 请求与解密 ----------
def b64d(s):
    """base64 解码，兼容缺失 padding 和 urlsafe 变体"""
    if isinstance(s, str):
        s = s.strip()
        # 修复了丢失的乘号和补齐算法
        s += "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(s)
    except Exception:
        return base64.urlsafe_b64decode(s)

def _extract_json(raw):
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    try:
        return json.loads(text)
    except ValueError:
        # 无标准 PKCS7 填充或首尾有杂讯时，截取 JSON 主体
        return json.loads(text[text.find("{"):text.rfind("}") + 1])

def fetch(is_cn):
    body = json.dumps({"is_from_cn": is_cn, "platform": "android", "is_list_mode": False}).encode()
    headers = {"User-Agent": "Dart/3.10", "Content-Type": "application/json",
               "x-device-id": DEVICE, "authorization": TOKEN}
    req = urllib.request.Request(API, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=60, context=ssl.create_default_context()) as r:
        res = json.loads(r.read())
    data = res.get("data") if isinstance(res.get("data"), dict) else {}
    # 兼容三种返回形态：AES 加密包 / data 直接是配置 / 配置在根节点
    if "encrypted" in data:
        raw = decrypt(KEY, b64d(data["iv"]), b64d(data["encrypted"]))
        try:
            raw = unpad(raw)
        except ValueError:
            pass  # 后端取消标准填充也能解析
        return _extract_json(raw)
    for cand in (data, res):
        if isinstance(cand, dict) and "outbounds" in cand:
            return cand
    raise ValueError(f"无法识别的响应结构 data_keys={list(data)}")

# ---------- 生成链接 ----------
def _pick(d, *keys, default=""):
    """按顺序取第一个非空字段，兼容后端字段改名"""
    if not isinstance(d, dict):
        return default
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default

def _tls_block(n):
    t = n.get("tls") or n.get("tls_settings") or n.get("security_settings") or {}
    if not isinstance(t, dict):
        t = {}
    r = t.get("reality") or n.get("reality") or {}
    if not isinstance(r, dict):
        r = {}
    return t, r, bool(r.get("enabled"))

def _common_params(n, params):
    """TLS / Reality / ALPN 通用参数"""
    t, r, is_reality = _tls_block(n)
    if is_reality:
        params["security"] = "reality"
        params["pbk"] = _pick(r, "public_key", "publicKey")
        params["sid"] = _pick(r, "short_id", "shortId")
    elif t.get("enabled") is False:
        params["security"] = "none"
    elif t:
        params["security"] = "tls"
    else:
        params["security"] = "none"
    sni = _pick(t, "server_name", "sni", "serverName") or _pick(n, "sni", "peer")
    if sni:
        params["sni"] = sni
    if params.get("security") in ("tls", "reality"):
        utls = t.get("utls") if isinstance(t.get("utls"), dict) else {}
        params["fp"] = _pick(utls, "fingerprint") or _pick(n, "fingerprint", "client-fingerprint") or "chrome"
    if t.get("insecure") is True or t.get("allow_insecure") is True:
        params["allowInsecure"] = "1"
    alpn = t.get("alpn") or n.get("alpn")
    if isinstance(alpn, list):
        alpn = ",".join(str(a) for a in alpn if a)
    if alpn:
        params["alpn"] = alpn
    return params

def _transport_params(n, params):
    """传输层参数，覆盖 ws / grpc / httpupgrade / xhttp / tcp"""
    tr = n.get("transport") or n.get("stream_settings") or {}
    if not isinstance(tr, dict):
        tr = {}
    ttype = _pick(tr, "type") or _pick(n, "transport_type") or "tcp"
    if str(ttype).lower() in ("raw", "stream"):
        ttype = "tcp"
    params["type"] = ttype
    hdrs = tr.get("headers") if isinstance(tr.get("headers"), dict) else {}
    host = _pick(hdrs, "Host", "host") or _pick(tr, "host", "Host")
    if ttype == "ws":
        params["path"] = _pick(tr, "path", "ws_path", "wsPath")
        if host:
            params["host"] = host
    elif ttype in ("httpupgrade", "xhttp", "http"):
        params["path"] = _pick(tr, "path")
        if host:
            params["host"] = host
        if ttype == "http" and tr.get("method"):
            params["method"] = tr["method"]
    elif ttype == "grpc":
        params["serviceName"] = _pick(tr, "serviceName", "service_name")
        if tr.get("mode"):
            params["mode"] = tr["mode"]
    else:
        params["headerType"] = "none"
    return params

def _build(scheme, userinfo, host, port, params, tag, user_safe=""):
    if not host or not port:
        raise ValueError("缺少 server/server_port")
    userinfo = urllib.parse.quote(str(userinfo), safe=user_safe)
    q = urllib.parse.urlencode({k: v for k, v in params.items() if v not in ("", None, False)})
    url = f"{scheme}://{userinfo}@{host}:{port}"
    if q:
        url += f"?{q}"
    return f"{url}#{urllib.parse.quote(tag)}"

def make_uri(n, prefix):
    typ = str(n.get("type") or "").lower()
    tag = f"{prefix}{_pick(n, 'tag', 'name', default='node')}"
    host, port = _pick(n, "server", "address", "add", "host"), _pick(n, "server_port", "port", "serverPort")

    if typ == "vless":
        params = {"encryption": "none"}
        flow = _pick(n, "flow")
        if flow:
            params["flow"] = flow
        _common_params(n, params)
        _transport_params(n, params)
        return _build("vless", _pick(n, "uuid", "id", "user_id"), host, port, params, tag)

    if typ == "trojan":
        params = {}
        _common_params(n, params)
        _transport_params(n, params)
        params.pop("flow", None)
        return _build("trojan", _pick(n, "password", "passwd", "pass", "uuid"), host, port, params, tag)

    if typ in ("hysteria2", "hy2"):
        t, _, _ = _tls_block(n)
        params = {"insecure": "1"}
        sni = _pick(t, "server_name", "sni") or _pick(n, "sni", "peer")
        if sni:
            params["sni"] = sni
        alpn = t.get("alpn") or n.get("alpn")
        if isinstance(alpn, list):
            alpn = ",".join(str(a) for a in alpn if a)
        if alpn:
            params["alpn"] = alpn
        obfs = _pick(n, "obfs") or _pick(t, "obfs")
        if obfs:
            params["obfs"] = obfs
            params["obfs-password"] = _pick(n, "obfs_password", "obfs-password") or _pick(t, "obfs_password", "obfs-password")
        ports = _pick(n, "ports", "mport")
        if ports:
            params["mport"] = ports
        return _build("hysteria2", _pick(n, "password", "auth", "auth_str", "uuid"), host, port, params, tag)

    if typ in ("shadowsocks", "ss"):
        method = _pick(n, "method", "cipher")
        pwd = _pick(n, "password", "passwd", "pass")
        userinfo = base64.urlsafe_b64encode(f"{method}:{pwd}".encode()).decode()
        params = {}
        plugin = _pick(n, "plugin")
        if plugin:
            params["plugin"] = plugin
        return _build("ss", userinfo, host, port, params, tag)

    if typ == "tuic":
        params = {}
        _common_params(n, params)
        for src, dst in (("congestion_control", "congestion_control"),
                         ("udp_relay_mode", "udp_relay_mode"),
                         ("zero_rtt_handshake", "zero_rtt")):
            v = _pick(n, src)
            if v not in ("", None):
                params[dst] = v
        if t_get_insecure(n):
            params["allow_insecure"] = "1"
        userinfo = f"{_pick(n, 'uuid')}:{_pick(n, 'password')}"
        return _build("tuic", userinfo, host, port, params, tag, user_safe=":")

    return None

def t_get_insecure(n):
    t, _, _ = _tls_block(n)
    return t.get("insecure") is True or n.get("allow_insecure") is True

# ---------- 主流程 ----------
GROUP_TYPES = {"urltest", "selector", "direct", "block", "dns"}

def main():
    all_links, skipped = [], []
    for is_cn, label in [(True, "星链_CN_"), (False, "星链_Global_")]:
        print(f"[*] 获取 {'国内' if is_cn else '国际'} 节点...")
        try:
            cfg = fetch(is_cn)
        except Exception as e:
            print(f"    [失败] {e}")
            continue
        outbounds = cfg.get("outbounds") or cfg.get("nodes") or cfg.get("proxies") or []
        ok = 0
        for n in outbounds:
            if not isinstance(n, dict) or str(n.get("type") or "").lower() in GROUP_TYPES:
                continue
            try:
                u = make_uri(n, label)
            except Exception as e:
                skipped.append(f"{_pick(n, 'tag', 'name', default='?')}({_pick(n, 'type')}): {e}")
                continue
            if u:
                all_links.append(u)
                ok += 1
            else:
                skipped.append(f"{_pick(n, 'tag', 'name', default='?')}: 暂不支持的类型 {_pick(n, 'type')}")
        print(f"    [+] {ok} 个节点" + (f"（跳过 {len(skipped)} 个）" if skipped else ""))

    if not all_links:
        sys.exit("错误：未获取到任何节点")

    # 写入沙盒自动提取目录
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(all_links) + "\n")
        
    print(f"[+] 抓取完成，共 {len(all_links)} 个节点已输出供聚合。")

if __name__ == "__main__":
    main()
