#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Alice (爱丽丝) 插件：一个账号领一个订阅链接，转成节点写入聚合输出。
# @interval: 12h
聚合插件约定：
  依赖 requests + pyyaml；默认 --outdir output；日志不打印链接/token/密码；
  账号缓存 ../vault_repo/alice_bank.json；优先复用，订阅失效才注册新账号；
  退出码 0=有节点，2=失败。
"""
import argparse
import base64
import json
import os
import random
import re
import string
import sys
import time
import urllib.parse as _up

BASE = "https://two.harnesscom.com"
API = BASE + "/api/v1"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36"
SUB_RE = re.compile(r"https://sub\.harnesscom\.com/sub/[A-Za-z0-9_\.\-]+", re.I)
BUDGET = int(os.environ.get("ALICE_BUDGET_SECONDS", "300"))
_ENDPOINT = time.monotonic() + BUDGET
PROXY = None
DOMAIN = "mailo.icu"


class _BudgetExceeded(RuntimeError):
    pass


class _SubscriptionExpired(RuntimeError):
    pass


def _remaining():
    return max(0.0, _ENDPOINT - time.monotonic())


def _check():
    if _remaining() < 1:
        raise _BudgetExceeded("总时间预算已耗尽")


def _timeout():
    _check()
    return (min(8.0, _remaining()), min(20.0, _remaining()))


def _redact(text):
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+", r"\1[hidden]", str(text))
    text = re.sub(r"(?i)(sub\.harnesscom\.com/sub/)[A-Za-z0-9._\-]+", r"\1[hidden]", text)
    text = re.sub(r"(?i)((?:password|token|authorization)\W{0,4})[^,\s\"}\n]+", r"\1[hidden]", text)
    return text[:180]


def _rand_email():
    rng = random.SystemRandom()
    tail = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    return "alice%s@%s" % (tail, DOMAIN)


def _rand_password():
    rng = random.SystemRandom()
    pool = string.ascii_letters + string.digits + "#-"
    return "Aa1" + "".join(rng.choice(pool) for _ in range(13))


def _vault_dir():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vault_repo")


def _bank_path():
    return os.path.join(_vault_dir(), "alice_bank.json")


def _load_bank():
    try:
        with open(_bank_path(), encoding="utf-8") as f:
            entries = json.load(f)
        return entries if isinstance(entries, list) else []
    except Exception:
        return []


def _save_bank(entries):
    os.makedirs(_vault_dir(), exist_ok=True)
    keep = []
    for entry in entries[:1]:
        if isinstance(entry, dict) and entry.get("email") and entry.get("password") and entry.get("sub_link"):
            keep.append({"email": entry["email"], "password": entry["password"],
                         "sub_link": entry["sub_link"], "ts": entry.get("ts") or 0})
    with open(_bank_path(), "w", encoding="utf-8") as f:
        json.dump(keep, f, ensure_ascii=False, indent=1)


def _new_session():
    import requests
    session = requests.Session()
    session.trust_env = not bool(PROXY)
    if PROXY:
        session.proxies.update({"http": PROXY, "https": PROXY})
    return session


def _req(session, method, url, token=None, payload=None):
    _check()
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    r = session.request(method, url, json=payload, headers=headers, timeout=_timeout())
    r.raise_for_status()
    return r


def _claim_link(session, email, password):
    """注册/登录 → 等订单（90秒）→ 抽一条基础订阅链接；不打印链接。"""
    token = None
    try:
        r = _req(session, "POST", API + "/auth/register",
                 payload={"email": email, "password": password, "agreement_accepted": True})
        token = (r.json().get("data") or {}).get("token")
    except Exception as error:
        # 上次注册已到站、响应丢失时，同一身份可能返回冲突；先尝试登录。
        response = getattr(error, "response", None)
        if response is None or response.status_code not in (400, 409, 422):
            raise
    if not token:
        r = _req(session, "POST", API + "/auth/login", payload={"email": email, "password": password})
        token = (r.json().get("data") or {}).get("token")
    if not token:
        raise RuntimeError("auth: 无 token")
    deadline = time.monotonic() + 90
    rows = []
    while time.monotonic() < deadline and _remaining() > 5:
        r = _req(session, "GET", API + "/orders?page=1&page_size=20", token=token)
        rows = r.json().get("data") or []
        if rows:
            order_no = rows[0]["order_no"]
            break
        print("    · orders: 等待订单...", flush=True)
        time.sleep(4)
    if not rows:
        raise RuntimeError("orders: 90 秒未出现订单")
    r = _req(session, "GET", API + "/orders/" + order_no, token=token)
    links = SUB_RE.findall(json.dumps(r.json().get("data") or {}, ensure_ascii=False))
    base = [u for u in links if not u.endswith(("/clash_meta", "/sing_box", "/xray", "/links"))]
    link = (base or links or [None])[0]
    if not link:
        raise RuntimeError("order: 无链接")
    return link


def register():
    """单账号领取；网络重试始终复用同一身份，不批量注册。"""
    email, password = _rand_email(), _rand_password()
    for attempt in range(2):
        try:
            _check()
            with _new_session() as session:
                link = _claim_link(session, email, password)
            return {"email": email, "password": password, "sub_link": link, "ts": int(time.time())}
        except _BudgetExceeded:
            raise
        except Exception as error:
            if attempt == 1:
                raise RuntimeError("register: " + _redact(error)) from None
            print("    · register: 重试一次 (" + _redact(error) + ")", flush=True)
            time.sleep(2)


def fetch_nodes(sub_link):
    """下载基础链接的 /clash_meta YAML 并解析成节点 URI 列表。"""
    import yaml
    config = None
    last_error = "subscription: 未下载"
    for _ in range(2):
        try:
            with _new_session() as session:
                r = session.get(sub_link.rstrip("/") + "/clash_meta",
                                headers={"User-Agent": "clash-verge/v1.3.8",
                                         "Accept": "*/*", "referer": BASE + "/"},
                                timeout=_timeout())
                if r.status_code in (401, 404, 410):
                    raise _SubscriptionExpired("subscription: HTTP %s" % r.status_code)
                r.raise_for_status()
                config = yaml.safe_load(r.text)
                break
        except (_BudgetExceeded, _SubscriptionExpired):
            raise
        except Exception as error:
            last_error = "subscription: " + type(error).__name__ + " " + _redact(error)
            time.sleep(1)
    if config is None:
        return [], last_error
    return _parse_nodes(config)


def _parse_nodes(config):
    """解析 Clash YAML/字典；不联网。"""
    if isinstance(config, str):
        import yaml
        try:
            config = yaml.safe_load(config)
        except yaml.YAMLError:
            return [], "subscription: YAML 格式错误"
    uris = []
    proxies = config.get("proxies", []) if isinstance(config, dict) else []
    if not isinstance(proxies, list):
        return [], "subscription: absent proxies"
    for proxy in proxies:
        try:
            uris.append(_to_uri(proxy))
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
    if not uris:
        return [], "subscription: 无有效节点"
    return list(dict.fromkeys(uris)), None


def _to_uri(proxy):
    """把单个 Clash 代理转成标准 URI，保持现有 wula.py 的字段覆盖。"""
    kind = str(proxy.get("type", "")).lower()
    server = str(proxy.get("server", ""))
    port = int(proxy.get("port", 0))
    secret = str(proxy.get("uuid") or proxy.get("password") or "")
    name = _up.quote(str(proxy.get("name", "node")), safe="")
    sni = proxy.get("sni") or proxy.get("servername") or ""
    if not server or server in ("localhost", "127.0.0.1") or not 0 < port < 65536 or not secret:
        raise ValueError("invalid node")
    if ":" in server and not server.startswith("["):
        server = "[%s]" % server
    sni_q = _up.quote(str(sni), safe="")
    secret_q = _up.quote(secret, safe="")
    insecure = "1" if proxy.get("skip-cert-verify", False) else "0"
    if kind in ("hysteria2", "hy2"):
        params = {"insecure": insecure, "sni": sni}
        for key in ("obfs", "obfs-password", "up", "down"):
            if proxy.get(key) is not None:
                params[key] = proxy[key]
        return "hy2://%s@%s:%s?%s#%s" % (secret_q, server, port, _up.urlencode(params), name)
    if kind == "anytls":
        return "anytls://%s@%s:%s/?insecure=%s&type=tcp&fp=%s&sni=%s#%s" % (
            secret_q, server, port, insecure,
            _up.quote(str(proxy.get("client-fingerprint", "chrome")), safe=""), sni_q, name)
    if kind == "trojan":
        params = {"allowInsecure": insecure, "sni": sni, "type": proxy.get("network", "tcp")}
        ws = proxy.get("ws-opts") or {}
        if ws.get("path"):
            params["path"] = ws["path"]
        if (ws.get("headers") or {}).get("Host"):
            params["host"] = ws["headers"]["Host"]
        return "trojan://%s@%s:%s?%s#%s" % (secret_q, server, port, _up.urlencode(params), name)
    if kind == "ss":
        raw = ("%s:%s" % (proxy.get("cipher", "aes-128-gcm"), secret)).encode()
        return "ss://%s@%s:%s#%s" % (base64.b64encode(raw).decode().rstrip("="), server, port, name)
    if kind == "vless":
        bits = ["type=" + proxy.get("network", "tcp"), "encryption=none"]
        if sni_q:
            bits.append("sni=" + sni_q)
        fp = proxy.get("client-fingerprint")
        if fp:
            bits.append("fp=" + _up.quote(str(fp), safe=""))
        ws = proxy.get("ws-opts") or {}
        if ws.get("path"):
            bits.append("path=" + _up.quote(str(ws["path"]), safe=""))
        host = (ws.get("headers") or {}).get("Host")
        if host:
            bits.append("host=" + _up.quote(str(host), safe=""))
        if proxy.get("flow"):
            bits.append("flow=" + _up.quote(str(proxy["flow"]), safe=""))
        grpc = proxy.get("grpc-opts") or {}
        if grpc.get("grpc-service-name"):
            bits.append("serviceName=" + _up.quote(str(grpc["grpc-service-name"]), safe=""))
        reality = proxy.get("reality-opts") or {}
        if reality:
            bits.append("security=reality")
            bits.append("pbk=" + _up.quote(str(reality.get("public-key", "")), safe=""))
            if reality.get("short-id") is not None:
                bits.append("sid=" + _up.quote(str(reality["short-id"]), safe=""))
        elif proxy.get("tls"):
            bits.append("security=tls&allowInsecure=" + insecure)
        if proxy.get("alpn"):
            bits.append("alpn=" + _up.quote(",".join(proxy["alpn"]), safe=""))
        return "vless://%s@%s:%s?%s#%s" % (secret_q, server, port, "&".join(bits), name)
    if kind == "vmess":
        info = {"add": str(proxy.get("server")), "port": port, "id": secret,
                "ps": str(proxy.get("name", "node")), "aid": str(proxy.get("alterId", 0) or 0),
                "net": proxy.get("network", "tcp"), "type": "none",
                "host": str((proxy.get("ws-opts") or {}).get("headers", {}).get("Host", proxy.get("server"))),
                "path": (proxy.get("ws-opts") or {}).get("path", "/"),
                "tls": "tls" if proxy.get("tls") else "none", "sni": str(sni), "v": "2"}
        return "vmess://" + base64.b64encode(json.dumps(info, separators=(",", ":")).encode()).decode()
    if kind == "tuic":
        return "tuic://%s:%s@%s:%s?sni=%s&congestion_control=cubic&udp_relay_mode=native#%s" % (
            secret_q, _up.quote(str(proxy.get("password", secret)), safe=""), server, port, sni_q, name)
    raise ValueError("unsupported " + kind)


def main(argv=None):
    global PROXY, DOMAIN, _ENDPOINT
    parser = argparse.ArgumentParser(description="单订阅转明文节点，每行一个 URI")
    parser.add_argument("--outdir", default="output")
    parser.add_argument("--proxy", default=os.environ.get("ALICE_PROXY"))
    parser.add_argument("--domain", default=os.environ.get("ALICE_DOMAIN", "mailo.icu"))
    args = parser.parse_args(argv)
    DOMAIN, PROXY = args.domain, args.proxy
    _ENDPOINT = time.monotonic() + BUDGET
    os.makedirs(args.outdir, exist_ok=True)
    nodes_path = os.path.join(args.outdir, "nodes.txt")
    # 不把上次的节点冒充本次抓取成功；聚合器自己保存失败时的旧缓存。
    with open(nodes_path, "w", encoding="utf-8") as handle:
        handle.write("")
    if PROXY:
        print("[*] 使用显式代理（地址隐藏）", flush=True)
    try:
        bank = _load_bank()[:1]
        if bank and isinstance(bank[0], dict) and SUB_RE.fullmatch(bank[0].get("sub_link", "")):
            entry = bank[0]
            print("[*] 复用一条私有缓存订阅", flush=True)
        else:
            print("[*] 领取一个账号、一条订阅", flush=True)
            entry = register()
            _save_bank([entry])
        try:
            uris, error = fetch_nodes(entry["sub_link"])
        except _SubscriptionExpired:
            if not bank:
                raise
            print("[*] 缓存订阅已失效，替换为一个新账号", flush=True)
            entry = register()
            _save_bank([entry])
            uris, error = fetch_nodes(entry["sub_link"])
        if not uris:
            raise RuntimeError(error or "subscription: 无有效节点")
        entry["ts"] = int(time.time())
        _save_bank([entry])
        with open(nodes_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(uris) + "\n")
        print("[+] 单订阅 -> %d 条明文节点 -> %s" % (len(uris), nodes_path), flush=True)
        return 0
    except Exception as error:
        print("[!] 本次失败：" + _redact(error), flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
