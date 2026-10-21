# main_engine.py
import os
import re
import ast
import json
import time
import glob
import shutil
import base64
import hashlib
import subprocess
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, unquote, quote, parse_qs
import yaml

# 路径配置
PLUGIN_DIR = "plugins"
VAULT_DIR = "vault_repo"
STATE_FILE = os.path.join(VAULT_DIR, "cache_state.json")
SANDBOX_DIR = "temp_sandbox"
PRE_TEST_FILE = "pre_test_nodes.txt"

MAX_FAIL_STREAK = 3
# 测速存活延迟阈值（毫秒）：超过此值的节点判为大卡/不可用剔除。有 ping 值才判定；lost=0 但未报 ping 的不误杀。
MAX_LATENCY_MS = 1000
VALID_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://", "hysteria://", "hysteria2://", "hy2://", "tuic://", "wg://", "anytls://")

PLUGIN_TAGS = {
    "de": "DE", "devpn": "DE", "dsfunique": "DE",
    "ipow": "iPoW", "iPow": "iPoW",
    "lanmao": "lanmao", "蓝猫": "lanmao",
    "safevpn": "safevpn",
    "sulian": "sulian", "速连": "sulian",
    "yes": "yes", "YesVPN": "yes",
    "小满": "小满", "xiaoman": "small",
    "银狐": "银狐", "yinhu": "银狐", "xunhu": "银狐",
    "cainiao": "cainiao", "菜鸟": "cainiao", "__": "cainiao",
    "Surfer": "SF", "surfer": "SF",
    "fengniao": "fengniao", "蜂鸟": "fengniao",
    "wula": "wula", "乌拉": "wula", "ulavpn": "wula",
}

def plugin_tag(script_name):
    stem = os.path.splitext(os.path.basename(script_name))[0]
    return PLUGIN_TAGS.get(stem, stem)

def get_beijing_time():
    tz_bj = timezone(timedelta(hours=8))
    return datetime.now(tz_bj).strftime("%Y-%m-%d %H:%M:%S")

def parse_interval(py_path):
    default_sec = 50 * 60
    try:
        with open(py_path, "r", encoding="utf-8", errors="ignore") as f:
            for _ in range(5):
                line = f.readline()
                match = re.search(r"@interval\s*:\s*(\d+)\s*([mhdMHD])", line)
                if match:
                    val, unit = int(match.group(1)), match.group(2).lower()
                    if unit == 'm': return val * 60
                    if unit == 'h': return val * 3600
                    if unit == 'd': return val * 86400
    except Exception:
        pass
    return default_sec

def format_interval(sec):
    if sec % 86400 == 0: return f"{sec // 86400}天"
    if sec % 3600 == 0: return f"{sec // 3600}小时"
    return f"{sec // 60}分钟"

def try_b64_decode(s):
    s = s.strip()
    if not s: return None
    s = re.sub(r'[\s\r\n]+', '', s)
    if len(s) < 8: return None
    try:
        s_pad = s + '=' * ((4 - len(s) % 4) % 4)
        dec = base64.b64decode(s_pad, validate=False)
        text = dec.decode('utf-8', errors='ignore')
        if text and all(ord(c) >= 32 or c in '\r\n\t' for c in text):
            return text
    except Exception: pass
    try:
        s2 = s.replace('-', '+').replace('_', '/')
        s2_pad = s2 + '=' * ((4 - len(s2) % 4) % 4)
        dec = base64.b64decode(s2_pad)
        text = dec.decode('utf-8', errors='ignore')
        if text and all(ord(c) >= 32 or c in '\r\n\t' for c in text):
            return text
    except Exception: pass
    return None

def quote_safe(s):
    return quote(s)

def clash_proxy_to_uri(p):
    try:
        ptype = p.get("type", "").lower()
        name = quote_safe(str(p.get("name", "Clash_Node")))
        server = p.get("server", "")
        port = p.get("port", "")
        if not server or not port: return None
        if ptype == "vmess":
            v_json = {
                "v": "2", "ps": p.get("name", "VMess"), "add": server, "port": str(port),
                "id": p.get("uuid", ""), "aid": str(p.get("alterId", 0)),
                "net": p.get("network", "tcp"), "type": "none", "tls": "tls" if p.get("tls") else ""
            }
            if p.get("servername"): v_json["sni"] = p["servername"]
            ws_opts = p.get("ws-opts", {})
            if ws_opts:
                v_json["path"] = ws_opts.get("path", "/")
                v_json["host"] = ws_opts.get("headers", {}).get("Host", "")
            return f"vmess://{base64.b64encode(json.dumps(v_json).encode()).decode()}"
        elif ptype == "vless":
            tls = "tls" if p.get("tls") else "none"
            return f"vless://{p.get('uuid','')}@{server}:{port}?security={tls}&type={p.get('network','tcp')}&sni={p.get('servername','')}#{name}"
        elif ptype == "trojan":
            return f"trojan://{p.get('password','')}@{server}:{port}?sni={p.get('sni','')}#{name}"
        elif ptype == "ss":
            userinfo = base64.urlsafe_b64encode(f"{p.get('cipher','aes-256-gcm')}:{p.get('password','')}".encode()).decode().rstrip("=")
            return f"ss://{userinfo}@{server}:{port}#{name}"
        elif ptype in ("hysteria2", "hy2"):
            return f"hysteria2://{p.get('password','')}@{server}:{port}?sni={p.get('sni','')}&insecure=1#{name}"
    except Exception: pass
    return None

def _contains_scheme(text):
    return any(sch in text for sch in VALID_SCHEMES)

def _deep_extract(content, depth=0):
    if depth > 3: return []
    content = content.strip()
    if not content: return []
    nodes, seen = [], set()
    for line in content.splitlines():
        line = line.strip()
        if not line: continue
        if line.startswith(VALID_SCHEMES):
            if line not in seen:
                seen.add(line)
                nodes.append(line)
            continue
        sub_dec = try_b64_decode(line)
        if sub_dec:
            for n in _deep_extract(sub_dec, depth + 1):
                if n not in seen:
                    seen.add(n)
                    nodes.append(n)
    if not nodes and len(content) < 200000:
        whole_dec = try_b64_decode(content)
        if whole_dec and _contains_scheme(whole_dec):
            for n in _deep_extract(whole_dec, depth + 1):
                if n not in seen:
                    seen.add(n)
                    nodes.append(n)
    return nodes

def extract_nodes_from_text(content):
    nodes = []
    content = content.strip()
    if not content: return nodes
    yaml_nodes = []
    if "proxies:" in content:
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
                for p in data["proxies"]:
                    uri = clash_proxy_to_uri(p)
                    if uri: yaml_nodes.append(uri)
        except Exception: pass
    text_nodes = _deep_extract(content, 0)
    seen = set()
    for n in yaml_nodes + text_nodes:
        if n not in seen:
            seen.add(n)
            nodes.append(n)
    return nodes

def get_node_fingerprint(uri):
    try:
        if uri.startswith("vmess://"):
            b64 = uri[8:].split("#")[0]
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            return hashlib.md5(f"vmess://{data.get('add')}:{data.get('port')}:{data.get('id')}:{data.get('path','')}".encode()).hexdigest()
        else:
            return hashlib.md5(uri.split("#")[0].encode()).hexdigest()
    except Exception:
        return hashlib.md5(uri.encode()).hexdigest()

def extract_original_name(uri):
    try:
        if uri.startswith("vmess://"):
            b64 = uri[8:].split("#")[0].strip()
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            ps = str(data.get("ps", "")).strip()
            if ps: return unquote(ps)
        if "#" in uri:
            return unquote(uri.split("#", 1)[1]).strip()
    except Exception: pass
    return "未命名节点"

DEAD_UUID = "00000000-0000-0000-0000-000000000000"
BAD_HOSTS = {"127.0.0.1", "0.0.0.0", "localhost", "::1"}
BAD_PORTS = {"0", "1"}
_RE_HOST_PORT = re.compile(r'^[a-z0-9]+://[^@/]+@([^:/?#]+):(\d+)')

def filter_dead_pairs(nodes):
    out, dropped = [], 0
    for link in nodes:
        base = link.split("#", 1)[0].lower()
        bad = DEAD_UUID in base
        if not bad:
            m = re.match(_RE_HOST_PORT, base)
            if m and (m.group(1) in BAD_HOSTS or m.group(2) in BAD_PORTS):
                bad = True
        if bad: dropped += 1
        else: out.append(link)
    if dropped:
        print(f"🧹 死节点参数级预筛：剔除 {dropped} 个（全零uuid/回环地址/无效端口）")
    return out

DETECT_CITY = sorted([
    ("东京", "🇯🇵 东京"), ("大阪", "🇯🇵 大阪"), ("名古屋", "🇯🇵 名古屋"), ("札幌", "🇯🇵 札幌"),
    ("福冈", "🇯🇵 福冈"), ("横滨", "🇯🇵 横滨"), ("埼玉", "🇯🇵 埼玉"), ("TOKYO", "🇯🇵 东京"),
    ("OSAKA", "🇯🇵 大阪"), ("NAGOYA", "🇯🇵 名古屋"), ("NRT", "🇯🇵 东京"), ("KIX", "🇯🇵 大阪"), ("TYO", "🇯🇵 东京"),
    ("首尔", "🇰🇷 首尔"), ("釜山", "🇰🇷 釜山"), ("仁川", "🇰🇷 仁川"), ("SEOUL", "🇰🇷 首尔"), ("ICN", "🇰🇷 首尔"),
    ("台北", "🇹🇼 台北"), ("新北", "🇹🇼 新北"), ("高雄", "🇹🇼 高雄"), ("台中", "🇹🇼 台中"), ("TAIPEI", "🇹🇼 台北"), ("TPE", "🇹🇼 台北"),
    ("新加坡", "🇸🇬 新加坡"), ("狮城", "🇸🇬 新加坡"), ("SINGAPORE", "🇸🇬 新加坡"), ("SIN", "🇸🇬 新加坡"),
    ("雅加达", "🇮🇩 雅加达"), ("JAKARTA", "🇮🇩 雅加达"), ("CGK", "🇮🇩 雅加达"),
    ("吉隆坡", "🇲🇾 吉隆坡"), ("KUALA", "🇲🇾 吉隆坡"), ("KUL", "🇲🇾 吉隆坡"),
    ("曼谷", "🇹🇭 曼谷"), ("BANGKOK", "🇹🇭 曼谷"), ("BKK", "🇹🇭 曼谷"),
    ("马尼拉", "🇵🇭 马尼拉"), ("MANILA", "🇵🇭 马尼拉"), ("MNL", "🇵🇭 马尼拉"),
    ("河内", "🇻🇳 河内"), ("胡志明", "🇻🇳 胡志明"), ("HANOI", "🇻🇳 河内"), ("HCM", "🇻🇳 胡志明"),
    ("孟买", "🇮🇳 孟买"), ("班加罗尔", "🇮🇳 班加罗尔"), ("新德里", "🇮🇳 新德里"), ("MUMBAI", "🇮🇳 孟买"),
    ("迪拜", "🇦🇪 迪拜"), ("阿布扎比", "🇦🇪 阿布扎比"), ("DUBAI", "🇦🇪 迪拜"),
    ("法兰克福", "🇩🇪 法兰克福"), ("柏林", "🇩🇪 柏林"), ("慕尼黑", "🇩🇪 慕尼黑"), ("FRANKFURT", "🇩🇪 法兰克福"), ("FRA", "🇩🇪 法兰克福"),
    ("巴黎", "🇫🇷 巴黎"), ("马赛", "🇫🇷 马赛"), ("PARIS", "🇫🇷 巴黎"), ("CDG", "🇫🇷 巴黎"),
    ("伦敦", "🇬🇧 伦敦"), ("曼彻斯特", "🇬🇧 曼彻斯特"), ("LONDON", "🇬🇧 伦敦"), ("LHR", "🇬🇧 伦敦"),
    ("阿姆斯特丹", "🇳🇱 阿姆斯特丹"), ("AMS", "🇳🇱 阿姆斯特丹"),
    ("苏黎世", "🇨🇭 苏黎世"), ("日内瓦", "🇨🇭 日内瓦"),
    ("马德里", "🇪🇸 马德里"), ("巴塞罗那", "🇪🇸 巴塞罗那"),
    ("米兰", "🇮🇹 米兰"), ("罗马", "🇮🇹 罗马"),
    ("斯德哥尔摩", "🇸🇪 斯德哥尔摩"), ("赫尔辛基", "🇫🇮 赫尔辛基"),
    ("维也纳", "🇦🇹 维也纳"), ("莫斯科", "🇷🇺 莫斯科"), ("MOW", "🇷🇺 莫斯科"),
    ("多伦多", "🇨🇦 多伦多"), ("温哥华", "🇨🇦 温哥华"), ("蒙特利尔", "🇨🇦 蒙特利尔"), ("TORONTO", "🇨🇦 多伦多"), ("YVR", "🇨🇦 温哥华"),
    ("洛杉矶", "🇺🇸 洛杉矶"), ("圣克拉拉", "🇺🇸 圣克拉拉"), ("圣何塞", "🇺🇸 圣何塞"),
    ("西雅图", "🇺🇸 西雅图"), ("达拉斯", "🇺🇸 达拉斯"), ("纽约", "🇺🇸 纽约"), ("芝加哥", "🇺🇸 芝加哥"),
    ("凤凰城", "🇺🇸 凤凰城"), ("迈阿密", "🇺🇸 迈阿密"), ("硅谷", "🇺🇸 硅谷"),
    ("LAX", "🇺🇸 洛杉矶"), ("SEA", "🇺🇸 西雅图"), ("NYC", "🇺🇸 纽约"), ("SJC", "🇺🇸 圣何塞"), ("ORD", "🇺🇸 芝加哥"),
    ("圣保罗", "🇧🇷 圣保罗"), ("里约", "🇧🇷 里约"), ("SAO", "🇧🇷 圣保罗"),
    ("悉尼", "🇦🇺 悉尼"), ("墨尔本", "🇦🇺 墨尔本"), ("SYD", "🇦🇺 悉尼"),
    ("奥克兰", "🇳🇿 奥克兰"), ("约翰内斯堡", "🇿🇦 约翰内斯堡"), ("开普敦", "🇿🇦 开普敦")
], key=lambda x: -len(x[0]))

DETECT_CN = sorted([
    ("印度尼西亚", "🇮🇩 印尼"), ("澳大利亚", "🇦🇺 澳大利亚"), ("澳洲", "🇦🇺 澳大利亚"), ("台湾", "🇹🇼 台湾"),
    ("香港", "🇭🇰 香港"), ("HONGKONG", "🇭🇰 香港"), ("新加坡", "🇸🇬 新加坡"), ("SINGAPORE", "🇸🇬 新加坡"),
    ("日本", "🇯🇵 日本"), ("JAPAN", "🇯🇵 日本"), ("韩国", "🇰🇷 韩国"), ("KOREA", "🇰🇷 韩国"),
    ("美国", "🇺🇸 美国"), ("AMERICA", "🇺🇸 美国"), ("UNITED STATES", "🇺🇸 美国"),
    ("英国", "🇬🇧 英国"), ("ENGLAND", "🇬🇧 英国"), ("德国", "🇩🇪 德国"), ("GERMANY", "🇩🇪 德国"),
    ("法国", "🇫🇷 法国"), ("FRANCE", "🇫🇷 法国"), ("加拿大", "🇨🇦 加拿大"), ("CANADA", "🇨🇦 加拿大"),
    ("俄罗斯", "🇷🇺 俄罗斯"), ("RUSSIA", "🇷🇺 俄罗斯"), ("印度", "🇮🇳 印度"), ("INDIA", "🇮🇳 印度"),
    ("荷兰", "🇳🇱 荷兰"), ("NETHERLANDS", "🇳🇱 荷兰"), ("土耳其", "🇹🇷 土耳其"), ("TURKEY", "🇹🇷 土耳其"),
    ("泰国", "🇹🇭 泰国"), ("THAILAND", "🇹🇭 泰国"), ("越南", "🇻🇳 越南"), ("VIETNAM", "🇻🇳 越南"),
    ("马来西亚", "🇲🇾 马来西亚"), ("MALAYSIA", "🇲🇾 马来西亚"), ("菲律宾", "🇵🇭 菲律宾"), ("PHILIPPINES", "🇵🇭 菲律宾"),
    ("印尼", "🇮🇩 印尼"), ("INDONESIA", "🇮🇩 印尼"), ("巴西", "🇧🇷 巴西"), ("BRAZIL", "🇧🇷 巴西"),
    ("南非", "🇿🇦 南非"), ("SOUTH AFRICA", "🇿🇦 南非"), ("新西兰", "🇳🇿 新西兰"),
    ("意大利", "🇮🇹 意大利"), ("ITALY", "🇮🇹 意大利"), ("西班牙", "🇪🇸 西班牙"), ("SPAIN", "🇪🇸 西班牙"),
    ("瑞士", "🇨🇭 瑞士"), ("SWITZERLAND", "🇨🇭 瑞士"), ("瑞典", "🇸🇪 瑞典"), ("SWEDEN", "🇸🇪 瑞典"),
    ("波兰", "🇵🇱 波兰"), ("POLAND", "🇵🇱 波兰"), ("阿联酋", "🇦🇪 阿联酋"), ("UAE", "🇦🇪 阿联酋"),
    ("埃及", "🇪🇬 埃及"), ("EGYPT", "🇪🇬 埃及"), ("阿根廷", "🇦🇷 阿根廷"), ("ARGENTINA", "🇦🇷 阿根廷"),
    ("智利", "🇨🇱 智利"), ("墨西哥", "🇲🇽 墨西哥"), ("比利时", "🇧🇪 比利时"), ("奥地利", "🇦🇹 奥地利"),
    ("丹麦", "🇩🇰 丹麦"), ("芬兰", "🇫🇮 芬兰"), ("挪威", "🇳🇴 挪威"), ("捷克", "🇨🇿 捷克")
], key=lambda x: -len(x[0]))

DETECT_CC_BY_CODE = {
    "HK": "🇭🇰 香港", "TW": "🇹🇼 台湾", "JP": "🇯🇵 日本", "KP": "🇰🇵 朝鲜", "KR": "🇰🇷 韩国",
    "SG": "🇸🇬 新加坡", "US": "🇺🇸 美国", "GB": "🇬🇧 英国", "UK": "🇬🇧 英国", "DE": "🇩🇪 德国",
    "FR": "🇫🇷 法国", "CA": "🇨🇦 加拿大", "AU": "🇦🇺 澳大利亚", "RU": "🇷🇺 俄罗斯",
    "IN": "🇮🇳 印度", "NL": "🇳🇱 荷兰", "TR": "🇹🇷 土耳其", "TH": "🇹🇭 泰国",
    "VN": "🇻🇳 越南", "MY": "🇲🇾 马来西亚", "PH": "🇵🇭 菲律宾", "ID": "🇮🇩 印尼",
    "BR": "🇧🇷 巴西", "ZA": "🇿🇦 南非", "NZ": "🇳🇿 新西兰", "IT": "🇮🇹 意大利",
    "ES": "🇪🇸 西班牙", "CH": "🇨🇭 瑞士", "SE": "🇸🇪 瑞典", "PL": "🇵🇱 波兰",
    "AE": "🇦🇪 阿联酋", "EG": "🇪🇬 埃及", "AR": "🇦🇷 阿根廷", "CL": "🇨🇱 智利",
    "MX": "🇲🇽 墨西哥", "BE": "🇧🇪 比利时", "AT": "🇦🇹 奥地利", "DK": "🇩🇰 丹麦",
    "FI": "🇫🇮 芬兰", "NO": "🇳🇴 挪威", "CZ": "🇨🇿 捷克", "HU": "🇭🇺 匈牙利",
    "PT": "🇵🇹 葡萄牙", "RO": "🇷🇴 罗马尼亚", "UA": "🇺🇦 乌克兰", "SA": "🇸🇦 沙特"
}

def apply_new_node_name(uri, new_name):
    # 🚨 痛定思痛的修复：VMess 协议不支持尾部加 # 号！否则代理软件直接崩溃报 Invalid base64
    try:
        if uri.startswith("vmess://"):
            b64 = uri[8:].split("#")[0].strip()
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            data["ps"] = new_name
            # VMess 名字只藏在 json 里，不拼接在结尾！
            return f"vmess://{base64.b64encode(json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8')).decode('utf-8')}"
    except Exception: pass
    return f"{uri.split('#')[0]}#{quote_safe(new_name)}"

def apply_source_prefix(uri, tag):
    orig = extract_original_name(uri)
    if not orig or orig == "未命名节点": orig = tag
    orig = re.sub(r'[\U0001F1E6-\U0001F1FF]{2}', '', orig).strip()
    if orig.startswith("|"): orig = orig[1:].strip()
    if not orig: orig = tag
    if orig.startswith(tag): return uri
    return apply_new_node_name(uri, f"{tag}{orig}")

def uri_to_clash_proxy(uri):
    try:
        name = extract_original_name(uri)
        if uri.startswith("vmess://"):
            b64 = uri[8:].split("#")[0].strip()
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            proxy = {
                "name": d.get("ps", name), "type": "vmess", "server": d.get("add"),
                "port": int(d.get("port", 443)), "uuid": d.get("id"), "alterId": int(d.get("aid", 0)),
                "cipher": d.get("scy", "auto"), "udp": True, "tls": d.get("tls") == "tls",
                "skip-cert-verify": True, "network": d.get("net", "tcp")
            }
            if d.get("sni"): proxy["servername"] = d.get("sni")
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("host", d.get("add", ""))}}
            return proxy

        parsed = urlparse(uri)
        scheme, server, port = parsed.scheme.lower(), parsed.hostname, parsed.port or 443
        userinfo = unquote(parsed.username or "")
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if scheme == "vless":
            proxy = {
                "name": name, "type": "vless", "server": server, "port": int(port),
                "uuid": userinfo, "udp": True, "tls": q.get("security") in ("tls", "reality"),
                "network": q.get("type", "tcp"), "skip-cert-verify": True
            }
            if q.get("flow"): proxy["flow"] = q["flow"]
            if q.get("sni"): proxy["servername"] = q["sni"]
            if q.get("fp"): proxy["client-fingerprint"] = q["fp"]
            if q.get("security") == "reality":
                sid = q.get("sid", "") or ""
                if not re.fullmatch(r'[0-9a-fA-F]{2,16}', sid): sid = ""   # mihomo: hex偶数位≤16,否则空
                proxy["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": sid}
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", q.get("sni", server))}}
            return proxy

        elif scheme in ("hysteria2", "hy2"):
            proxy = {
                "name": name, "type": "hysteria2", "server": server, "port": int(port),
                "password": userinfo, "udp": True, "skip-cert-verify": True
            }
            if q.get("sni"): proxy["sni"] = q["sni"]
            if q.get("obfs"):
                ob = str(q["obfs"]).strip()
                if ob.startswith("{"):          # safevpn 系把整个 dict 字符串塞进 URI
                    try:
                        od = ast.literal_eval(ob)
                        proxy["obfs"] = od.get("type", "salamander")
                        if od.get("password"): proxy["obfs-password"] = od["password"]
                        elif q.get("obfs-password"): proxy["obfs-password"] = q["obfs-password"]
                    except Exception:
                        pass
                else:
                    proxy["obfs"] = ob
                    if q.get("obfs-password"): proxy["obfs-password"] = q["obfs-password"]
            return proxy

        elif scheme == "trojan":
            proxy = {
                "name": name, "type": "trojan", "server": server, "port": int(port),
                "password": userinfo, "udp": True, "skip-cert-verify": True
            }
            if q.get("sni"): proxy["sni"] = q["sni"]
            if q.get("type") == "ws":
                proxy["network"] = "ws"
                proxy["ws-opts"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", server)}}
            return proxy

        elif scheme == "anytls":
            proxy = {
                "name": name, "type": "anytls", "server": server, "port": int(port),
                "password": userinfo, "udp": True, "skip-cert-verify": True
            }
            if q.get("sni"): proxy["sni"] = q["sni"]
            if q.get("fp"): proxy["client-fingerprint"] = q["fp"]
            return proxy

        elif scheme == "ss":
            if ":" not in userinfo:
                dec = try_b64_decode(userinfo)
                if dec: userinfo = dec
            if ":" in userinfo:
                cipher, pwd = userinfo.split(":", 1)
                return {"name": name, "type": "ss", "server": server, "port": int(port), "cipher": cipher, "password": pwd, "udp": True}
    except Exception: pass
    return None

class _QStr(str):
    """强制带引号的字符串 —— 防 mihomo 端 yaml 把数字开头 hex/base64 字符串误解析成非 str"""
def _qstr_repr(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="'")
yaml.add_representer(_QStr, _qstr_repr, Dumper=yaml.SafeDumper)

def _quote_all(o):
    """递归把 proxies 及其子结构中的 str 全部换成 _QStr"""
    if isinstance(o, str): return _QStr(o)
    if isinstance(o, dict): return {k: _quote_all(v) for k, v in o.items()}
    if isinstance(o, list): return [_quote_all(v) for v in o]
    return o

def export_clash_yaml(final_nodes, out_path):
    proxies = [p for uri in final_nodes if (p := uri_to_clash_proxy(uri)) and p.get("server")]
    if not proxies: return 0
    proxies = _quote_all(proxies)
    proxy_names = [p["name"] for p in proxies]

    clash_Wait = {
        "mixed-port": 7890, "allow-lan": True, "mode": "rule", "log-level": "info",
        "unified-delay": True, "tcp-concurrent": True,
        "dns": {"enable": True, "ipv6": False, "enhanced-mode": "fake-ip", "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]},
        "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动优选", "🔯 故障转移"] + proxy_names},
            {"name": "⚡ 自动优选", "type": "url-test", "proxies": proxy_names, "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50},
            {"name": "🔯 故障转移", "type": "fallback", "proxies": proxy_names, "url": "http://www.gstatic.com/generate_204", "interval": 300}
        ],
        "rules": ["GEOIP,LAN,DIRECT,no-resolve", "GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"]
    }
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(clash_Wait, f, allow_unicode=True, sort_keys=False)
    return len(proxies)

# ================= Egern 导出（2.20.0 原生 schema） ==================
# 支持: vless tcp(VISION)+reality / vless wss / vless ws / vless tcp+tls
#       vmess ws/wss / hysteria2 / ss / trojan(+reality)
# 不支持则跳过: vless ws+reality(无此组合schema), vless xhttp(transport无此类型)
def _eg_parse_qs_single(qs):
    return {k: v[0] for k, v in parse_qs(qs, keep_blank_values=True).items()}

def _eg_hostport(hp):
    hp = hp.strip().split('/', 1)[0]   # anytls 等带 path: 111.x:5501/ → 111.x:5501
    m = re.match(r'^(?:\[(.+)\]|([^:\[\]]+?)):([0-9]+)$', hp)
    return ((m.group(1) or m.group(2)), int(m.group(3))) if m else (None, None)

def _eg_vless(uri):
    body = uri[8:]
    frag = ''
    if '#' in body: body, frag = body.split('#', 1)
    hp, _, qs = body.partition('?')
    if '@' not in hp: return None, 'no-uuid'
    uuid, hp = hp.rsplit('@', 1)
    host, port = _eg_hostport(hp)
    if not host: return None, 'bad-hostport'
    p = _eg_parse_qs_single(qs)
    net, sec = p.get('type', 'tcp'), p.get('security', 'none')
    name = unquote(frag) or f'vless-{host}'
    flow = p.get('flow') or None
    sni = p.get('sni') or p.get('host') or host
    entry = {'name': name, 'server': host, 'port': port, 'user_id': uuid}
    if net == 'ws':
        if sec == 'reality': return None, 'ws+reality-egern-no'
        w = {'path': p.get('path', '/'), 'headers': {'Host': p.get('host') or host}}
        if sec == 'tls':
            wss = {'path': w['path'], 'headers': w['headers'], 'sni': sni}
            return {'vless': {**entry, 'transport': {'wss': wss}}}, None
        return {'vless': {**entry, 'transport': {'ws': w}}}, None
    if net in ('tcp', 'raw', ''):
        tls = {}
        if sec == 'reality':
            need = p.get('pbk', '')
            if not need: return None, 'reality-no-pbk'
            tls = {'sni': sni, 'reality': {'public_key': need, 'short_id': p.get('sid', '') or '0'}}
        elif sec == 'tls':
            tls = {'sni': sni}
        if tls:
            return {'vless': {**entry, **({'flow': flow} if flow else {}), 'transport': {'tls': tls}}}, None
        return None, 'tcp-no-tls-egern-no'
    return None, f'net-{net}-egern-no'

def _eg_vmess(uri):
    raw = uri[8:]
    frag = ''
    if '#' in raw: raw, frag = raw.split('#', 1)
    base = raw.rstrip('=')
    s = base + '=' * ((4 - len(base) % 4) % 4)
    try:
        d = json.loads(base64.urlsafe_b64decode(s.encode()).decode('utf-8', 'ignore'))
    except Exception:
        return None, 'vmess-b64-fail'
    host, port = d.get('add'), int(d.get('port', 443) or 443)
    net, tls = d.get('net', 'tcp'), d.get('tls') == 'tls'
    name = unquote(frag) or d.get('ps') or f'vmess-{host}'
    if net == 'ws':
        w = {'path': d.get('path', '/'), 'headers': {'Host': d.get('host') or host}}
        if tls: w['sni'] = d.get('sni') or d.get('host') or host
        t = {'wss': w} if tls else {'ws': {'path': w['path'], 'headers': w['headers']}}
        return {'vmess': {'name': name, 'server': host, 'port': port,
                          'user_id': d.get('id'), 'security': 'auto',
                          'transport': t}}, None
    return None, f'vmess-{net}-egern-no'

def _eg_hy2(uri):
    if uri.startswith('hy2://'):
        uri = 'hysteria2://' + uri[len('hy2://'):]
    body = uri[len('hysteria2://'):]
    frag = ''
    if '#' in body: body, frag = body.split('#', 1)
    hp, _, qs = body.partition('?')
    if '@' not in hp: return None, 'bad-auth'
    auth, hp = hp.rsplit('@', 1)
    host, port = _eg_hostport(hp)
    if not host: return None, 'bad-hostport'
    p = _eg_parse_qs_single(qs)
    e = {'name': unquote(frag) or f'hy2-{host}', 'server': host, 'port': port, 'auth': auth}
    if p.get('sni'): e['sni'] = p['sni']
    if p.get('insecure') == '1': e['skip_tls_verify'] = True
    ob = str(p.get('obfs', '')).strip()
    obpw = p.get('obfs-password', '') or ''
    if ob.startswith('{'):                    # safevpn 系 dict 字符串
        try:
            od = ast.literal_eval(ob)
            if od.get('type') == 'salamander':
                e['obfs'] = 'salamander'
                if od.get('password'): e['obfs_password'] = od['password']
                elif obpw: e['obfs_password'] = obpw
        except Exception:
            pass
    elif ob == 'salamander':
        e['obfs'] = 'salamander'
        if obpw: e['obfs_password'] = obpw
    return {'hysteria2': e}, None

def _eg_anytls(uri):
    body = uri[9:]
    frag = ''
    if '#' in body: body, frag = body.split('#', 1)
    hp, _, qs = body.partition('?')
    if '@' not in hp: return None, 'bad-auth'
    auth, hp = hp.rsplit('@', 1)
    host, port = _eg_hostport(hp)
    if not host: return None, 'bad-hostport'
    p = _eg_parse_qs_single(qs)
    e = {'name': unquote(frag) or f'anytls-{host}', 'server': host, 'port': port, 'password': auth}
    if p.get('sni'): e['sni'] = p['sni']
    if p.get('insecure') == '1': e['skip_tls_verify'] = True
    return {'anytls': e}, None

_EG_PORT = [
    ('vless://', _eg_vless), ('vmess://', _eg_vmess), ('hysteria2://', _eg_hy2),
    ('hy2://', _eg_hy2), ('anytls://', _eg_anytls),
]

def export_egern_yaml(final_nodes, out_path):
    entries, drop = [], {}
    for uri in final_nodes:
        uri = uri.strip()
        if not uri: continue
        entry = None
        for scheme, fn in _EG_PORT:
            if uri.startswith(scheme):
                entry, why = fn(uri); break
        if entry is None:
            why = locals().get('why', 'unknown-scheme')
            drop[why] = drop.get(why, 0) + 1
            continue
        entries.append(entry)
    if not entries:
        print("⚠️ Egern 导出：0 条可用（全部组合不支持）")
        return 0
    names, seen, emitted = [], {}, ["proxies:"]

    def _dump(kv, indent):
        pad = '  ' * indent
        out = []
        for k, v in kv.items():
            if isinstance(v, dict):
                out.append(f'{pad}{k}:')
                out += _dump(v, indent + 1)
            elif isinstance(v, list):
                out.append(f'{pad}{k}: [{", ".join(json.dumps(x, ensure_ascii=False) for x in v)}]')
            elif isinstance(v, str) and not re.match(r'^[A-Za-z0-9_./:\-@ ]+$', v):
                out.append(f'{pad}{k}: {json.dumps(v, ensure_ascii=False)}')
            else:
                out.append(f'{pad}{k}: {v}')
        return out

    for e in entries:
        proto, d = list(e.items())[0]
        n = d['name']
        if n in seen:
            seen[n] += 1
            d['name'] = f'{n} ({seen[n]})'
        else:
            seen[n] = 1
        names.append(d['name'])
        emitted.append(f'  - {proto}:')
        emitted += _dump(d, 3)
    emitted += ['', 'policy-groups:',
                '- select:', '    name: "PROXY"', '    policies:', '      - "AUTO"']
    emitted += [f'      - "{n}"' for n in names]
    emitted += ['- auto_test:', '    name: "AUTO"', '    policies:']
    emitted += [f'      - "{n}"' for n in names]
    emitted += ['    interval: 300', '    tolerance: 100', '    timeout: 5',
                '    latency_test_url: "https://cp.cloudflare.com/generate_204"',
                '', 'rules:']
    for dom in ('qq.com', 'taobao.com', 'tmall.com', '163.com', '126.com',
                'tencent.com', 'baidu.com', 'alipay.com', 'juejin.cn',
                'aliyuncs.com', 'weixin.com', 'weixinbridge.com',
                'legolegolego.cn', 'lanzoui.com', 'douyin.com', 'xdrig.com'):
        emitted += ['  - domain_suffix:', f'      match: "{dom}"', '      policy: DIRECT']
    emitted += ['  - geoip:', '      match: "CN"', '      policy: DIRECT',
                '      no_resolve: true', '  - default:', '      policy: PROXY']
    try:
        yaml.safe_load("\n".join(emitted))  # 自检：不合法直接抛
    except Exception as e:
        print(f"⚠️ Egern YAML 自检失败 ({e})，跳过导出")
        return 0
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(emitted) + "\n")
    print(f"📱 Egern 导出：{len(entries)} 条 / 原始 {len(final_nodes)} 条，跳过 {sum(drop.values())} 条不支持组合")
    for k, v in sorted(drop.items(), key=lambda x: -x[1]):
        print(f"   · 跳过 {k}: {v} 条")
    return len(entries)

GIST_DESC = "poly-sub-backup"
GIST_FILENAME = "sub_base64.txt"

def export_wula_only(final_nodes, out_path, out_path_b64=None):
    """乌拉VPN 单独导出文件：按最终命名格式输出 / 单独订阅渠道"""
    out = []
    for uri in final_nodes:
        if not re.search(r"wula", extract_original_name(uri), re.I): continue
        out.append(uri)
    if not out:
        print("ℹ️ wula 单独导出：0 条（本次无 wula 来源节点）")
        return 0
    with open(out_path, "w", encoding="utf-8") as f: f.write("\n".join(out) + "\n")
    if out_path_b64:
        b64 = base64.b64encode("\n".join(out).encode("utf-8")).decode("utf-8")
        with open(out_path_b64, "w", encoding="utf-8") as f: f.write(b64)
    print(f"🦅 wula 单独导出：{len(out)} 条 → {out_path} (base64: {out_path_b64})")
    return len(out)

# ================= sing-box / Surge 导出 ==================
def _sb_ws_transport(p):
    w = p.get("ws-opts") or {}
    hdrs = w.get("headers") if isinstance(w.get("headers"), dict) else {}
    return {"type": "ws", "path": w.get("path", "/"), "headers": hdrs or {"Host": ""}}

def _sb_tls(p):
    tls = {"enabled": True}
    n = p.get("servername") or p.get("sni")
    if n: tls["server_name"] = n
    if p.get("skip-cert-verify"): tls["insecure"] = True
    ro = p.get("reality-opts")
    if ro:
        tls["reality"] = {"enabled": True, "public_key": ro.get("public-key", ""),
                          "short_id": ro.get("short-id", "")}
    if p.get("client-fingerprint"):
        tls["utls"] = {"enabled": True, "fingerprint": p["client-fingerprint"]}
    return tls

def _clash_to_singbox(p):
    t_, sv, pt = p["type"], p["server"], int(p["port"])
    if t_ == "vless":
        e = {"type": "vless", "tag": p["name"], "server": sv, "server_port": pt, "uuid": p.get("uuid", "")}
        if p.get("flow"): e["flow"] = p["flow"]
        if p.get("tls"): e["tls"] = _sb_tls(p)
        if p.get("network") == "ws": e["transport"] = _sb_ws_transport(p)
        if p.get("network") == "grpc":
            g = p.get("grpc-opts") or {}
            e["transport"] = {"type": "grpc", "service_name": g.get("grpc-service-name", "")}
        return e
    if t_ == "vmess":
        e = {"type": "vmess", "tag": p["name"], "server": sv, "server_port": pt,
             "uuid": p.get("uuid", ""), "security": p.get("cipher", "auto")}
        if p.get("tls"): e["tls"] = _sb_tls(p)
        if p.get("network") == "ws": e["transport"] = _sb_ws_transport(p)
        return e
    if t_ == "hysteria2":
        e = {"type": "hysteria2", "tag": p["name"], "server": sv, "server_port": pt, "password": p.get("password", "")}
        if p.get("obfs"):
            e["obfs"] = {"type": "salamander", "password": p.get("obfs-password", "")}
        e["tls"] = _sb_tls(p)
        return e
    if t_ == "ss":
        return {"type": "shadowsocks", "tag": p["name"], "server": sv, "server_port": pt,
                "method": p.get("cipher", "aes-256-gcm"), "password": p.get("password", "")}
    if t_ == "trojan":
        e = {"type": "trojan", "tag": p["name"], "server": sv, "server_port": pt, "password": p.get("password", "")}
        e["tls"] = _sb_tls(p)
        if p.get("network") == "ws": e["transport"] = _sb_ws_transport(p)
        return e
    if t_ == "anytls":
        e = {"type": "anytls", "tag": p["name"], "server": sv, "server_port": pt, "password": p.get("password", "")}
        e["tls"] = {"enabled": True}
        if p.get("sni"): e["tls"]["server_name"] = p["sni"]
        if p.get("skip-cert-verify"): e["tls"]["insecure"] = True
        return e
    if t_ == "anytls":
        e = {'name': n, 'server': sv, 'port': pt, 'password': p.get('password', '')}
        sni = p.get('sni')
        if sni: e['sni'] = sni
        if p.get('skip-cert-verify'): e['skip_tls_verify'] = True
        return {'anytls': e}
    return None

def export_singbox_json(final_nodes, out_path):
    out = []
    for uri in final_nodes:
        uri = uri.strip()
        if not uri: continue
        p = uri_to_clash_proxy(uri)
        if not p or not p.get("server"): continue
        e = _clash_to_singbox(p)
        if e: out.append(e)
    if not out:
        print("⚠️ sing-box 导出：0 条可用"); return 0
    names = [e["tag"] for e in out]
    doc = {
        "log": {"level": "warn"},
        "outbounds": [{"type": "selector", "tag": "PROXY", "outbounds": ["AUTO"] + names},
                      {"type": "urltest", "tag": "AUTO", "outbounds": names,
                       "url": "https://cp.cloudflare.com/generate_204", "interval": "5m"}] + out,
        "route": {"final": "PROXY", "auto_detect_interface": True}
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    print(f"🧩 sing-box 导出：{len(out)} 条 / 原始 {len(final_nodes)} 条")
    return len(out)

def _clash_to_surge_line(p):
    t_, sv, pt, n = p["type"], p["server"], int(p["port"]), p["name"]
    ncols = list(filter(None, []))
    if t_ == "vmess":
        parts = [f"{n} = vmess", sv, str(pt), f"username={p.get('uuid','')}", "vmess-aead=true"]
        if p.get("network") == "ws":
            w = p.get("ws-opts") or {}
            parts += ["ws=true", f"ws-path={w.get('path','/')}"]
            h = w.get("headers") or {}
            if h.get("Host"): parts.append(f"ws-headers=Host:{h['Host']}")
        if p.get("tls"): parts += ["tls=true", f"sni={p.get('servername') or p.get('sni') or sv}"]
        if p.get("skip-cert-verify"): parts.append("skip-cert-verify=true")
        parts.append("udp-relay=true")
        return ",".join(parts)
    if t_ == "hysteria2":
        parts = [f"{n} = hysteria2", sv, str(pt), f"password={p.get('password','')}"]
        sni = p.get("sni") or p.get("servername")
        if sni: parts.append(f"sni={sni}")
        opw = p.get("obfs-password")
        if p.get("obfs") and opw: parts += ["obfs=salamander", f"obfs-password={opw}"]
        if p.get("skip-cert-verify"): parts.append("skip-cert-verify=true")
        parts.append("udp-relay=true")
        return ",".join(parts)
    if t_ == "ss":
        return ",".join([f"{n} = shadowsocks", sv, str(pt),
                         f"encrypt-method={p.get('cipher','')}", f"password={p.get('password','')}", "udp-relay=true"])
    if t_ == "trojan":
        parts = [f"{n} = trojan", sv, str(pt), f"password={p.get('password','')}"]
        if p.get("sni"): parts.append(f"sni={p['sni']}")
        if p.get("network") == "ws":
            w = p.get("ws-opts") or {}
            parts += ["ws=true", f"ws-path={w.get('path','/')}"]
        parts.append("udp-relay=true")
        return ",".join(parts)
    return None

def export_surge_ini(final_nodes, out_path):
    body, nod = [], []
    for uri in final_nodes:
        uri = uri.strip()
        if not uri: continue
        p = uri_to_clash_proxy(uri)
        if not p or not p.get("server"): continue
        ln = _clash_to_surge_line(p)
        if ln:
            body.append(ln); nod.append(p["name"])
    if not body:
        print("⚠️ Surge 导出：0 条可用"); return 0
    conf = (["[General]", "loglevel = notify", "dns-server = system",
             "skip-proxy = 127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local",
             "", "[Proxy]"] + body
            + ["", "[Proxy Group]",
               "PROXY = select, AUTO, " + ", ".join(f'"{n}"' for n in nod),
               "AUTO = url-test, " + ", ".join(f'"{n}"' for n in nod)
               + ", url=http://www.gstatic.com/generate_204, interval=300",
               "", "[Rule]", "GEOIP,CN,DIRECT", "FINAL,PROXY"])
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(conf) + "\n")
    print(f"🖥 Surge/Surfboard 导出：{len(body)} 条（vless/xhttp Surge 不支持，已跳过）")
    return len(body)

def upload_to_gist_backup(content):
    import requests as _rq
    token = (os.environ.get("GIST_TOKEN") or "").strip()
    if not token: return None
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    try:
        r = _rq.get("https://api.github.com/gists", headers=headers, params={"per_page": 100}, timeout=30)
        gist_id = next((g["id"] for g in r.json() if g.get("description") == GIST_DESC and GIST_FILENAME in g.get("files", {})), None) if r.status_code == 200 else None
        payload = {"description": GIST_DESC, "public": False, "files": {GIST_FILENAME: {"content": content}}}
        r = _rq.patch(f"https://api.github.com/gists/{gist_id}", headers=headers, json=payload, timeout=30) if gist_id else _rq.post("https://api.github.com/gists", headers=headers, json=payload, timeout=30)
        if r.status_code in (200, 201): return f"https://gist.githubusercontent.com/raw/{r.json()['id']}/{GIST_FILENAME}"
    except Exception: pass
    return None

def detect_region_flag(raw_name):
    if not raw_name: return "🌐 其它"
    upper = raw_name.upper()
    for city, flag in DETECT_CITY:
        if city in raw_name: return flag
    for kw, flag in DETECT_CN:
        if kw in raw_name: return flag
    for emoji in re.findall(r'[\U0001F1E6-\U0001F1FF]{2}', raw_name):
        cc = chr(ord(emoji[0]) - 0x1F1E6 + 65) + chr(ord(emoji[1]) - 0x1F1E6 + 65)
        if cc in DETECT_CC_BY_CODE: return DETECT_CC_BY_CODE[cc]
    for cc in sorted(set(re.split(r'[^A-Za-z0-9]+', upper)) & set(DETECT_CC_BY_CODE)):
        return DETECT_CC_BY_CODE[cc]
    if any(k in upper for k in ("自动", "AUTO", "LOADBALANCE", "负载均衡", "随机", "BEST")): return "🌐 自动"
    return "🌐 其它"

def run_plugins_with_cache():
    os.makedirs(VAULT_DIR, exist_ok=True)
    state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f: state = json.load(f)
        except Exception: pass

    # 手动运行时强制全量重跑：由 workflow 传入 MANUAL_RUN=true（github.event_name == workflow_dispatch）
    manual_force = os.environ.get("MANUAL_RUN", "").strip().lower() in ("1", "true", "yes")
    if manual_force:
        print("🟢 [手动模式] 强制刷新所有插件（绕过 @interval 冷却）")

    now = int(time.time())
    py_files = sorted(glob.glob(os.path.join(PLUGIN_DIR, "*.py")))
    # 需要独占代理出口的插件排到最后（避免影响其它插件直连）。
    # 文件名以 _ 结尾（如 wula_.py）或配置在 LATE_RUN_PLUGINS 里 → 最后跑；
    # 没列进去的新插件默认按名字排在正常队列，绝不会被插到代理插件后面。
    _LATE_MARK = "_proxy."          # 文件名含此片段 → 最后执行
    _LATE_EXPLICIT = tuple(
        n.strip() for n in os.environ.get("LATE_RUN_PLUGINS", "wula.py").split(",") if n.strip()
    )

    def _is_late(p):
        b = os.path.basename(p)
        return b in _LATE_EXPLICIT or _LATE_MARK in b

    py_files.sort(key=lambda p: (_is_late(p), os.path.basename(p)))
    active_script_names = {os.path.basename(p) for p in py_files}

    for old_key in list(state.keys()):
        if old_key not in active_script_names: del state[old_key]

    all_raw_nodes = []
    plugin_reports = []

    print(f"📦 共扫描到 {len(py_files)} 个插件脚本")

    for py_path in py_files:
        script_name = os.path.basename(py_path)
        interval_sec = parse_interval(py_path)
        info = state.get(script_name, {})
        last_run = info.get("last_run", 0)
        cached_nodes = info.get("nodes", [])
        last_status = info.get("last_status", "✅ 正常更新")
        
        if cached_nodes:
            _tag = plugin_tag(script_name)
            cached_nodes = [apply_source_prefix(u, _tag) for u in cached_nodes]
        fail_count = info.get("fail_count", 0)
        elapsed = now - last_run

        if manual_force or elapsed + 180 >= interval_sec or not cached_nodes:
            print(f"🚀 [执行] {script_name} (设定间隔: {format_interval(interval_sec)}, 历史连续失败: {fail_count}次)")
            if os.path.exists(SANDBOX_DIR): shutil.rmtree(SANDBOX_DIR)
            os.makedirs(SANDBOX_DIR, exist_ok=True)
            shutil.copy(py_path, os.path.join(SANDBOX_DIR, script_name))
            
            try:
                proc = subprocess.run(["python", script_name], cwd=SANDBOX_DIR, capture_output=False, text=True, timeout=600)
                extracted = []
                for root, _, files in os.walk(SANDBOX_DIR):
                    for file in files:
                        if file == script_name or file.endswith(".pyc"): continue
                        try:
                            with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as rf:
                                extracted.extend(extract_nodes_from_text(rf.read()))
                        except Exception: pass

                if extracted:
                    tag = plugin_tag(script_name)
                    extracted = [apply_source_prefix(u, tag) for u in extracted]
                    print(f"   ✅ 成功从 {script_name} 提取到 {len(extracted)} 条节点，已重置失败计数！")
                    state[script_name] = {"last_run": now, "last_success": get_beijing_time(), "fail_count": 0, "last_status": "✅ 正常更新", "nodes": extracted}
                    all_raw_nodes.extend(extracted)
                    plugin_reports.append({"name": script_name, "interval": format_interval(interval_sec), "status": "✅ 正常更新", "count": len(extracted), "fail_count": 0, "advice": "运行良好"})
                else:
                    fail_count += 1
                    status_text = "🚨 疑似失效" if fail_count >= MAX_FAIL_STREAK else "⚠️ 本次空载"
                    print(f"   ⚠️ {script_name} 本次未产出有效节点 (连续失败 {fail_count} 次)")
                    if fail_count >= MAX_FAIL_STREAK: cached_nodes = []
                    state[script_name] = {"last_run": now, "last_success": info.get("last_success", "从未成功"), "fail_count": fail_count, "last_status": status_text, "nodes": cached_nodes}
                    all_raw_nodes.extend(cached_nodes)
                    plugin_reports.append({"name": script_name, "interval": format_interval(interval_sec), "status": status_text, "count": len(cached_nodes), "fail_count": fail_count, "advice": "🚨 建议下架删除！" if fail_count >= MAX_FAIL_STREAK else f"沿用旧缓存(失败{fail_count}次)"})
            except Exception as e:
                fail_count += 1
                status_text = "🚨 脚本崩溃" if fail_count >= MAX_FAIL_STREAK else "❌ 运行报错"
                print(f"   ❌ {script_name} 运行崩溃: {e} (连续失败 {fail_count} 次)")
                if fail_count >= MAX_FAIL_STREAK: cached_nodes = []
                state[script_name] = {"last_run": now, "last_success": info.get("last_success", "从未成功"), "fail_count": fail_count, "last_status": status_text, "nodes": cached_nodes}
                all_raw_nodes.extend(cached_nodes)
                plugin_reports.append({"name": script_name, "interval": format_interval(interval_sec), "status": status_text, "count": len(cached_nodes), "fail_count": fail_count, "advice": "🚨 建议下架删除！" if fail_count >= MAX_FAIL_STREAK else f"超时或报错(失败{fail_count}次)"})
        else:
            remain_min = (interval_sec - elapsed) // 60
            print(f"⏭️ [跳过] {script_name} 冷却中 (还需等待 {remain_min} 分钟)，读取缓存 ({len(cached_nodes)} 条)")
            all_raw_nodes.extend(cached_nodes)
            plugin_reports.append({"name": script_name, "interval": format_interval(interval_sec), "status": f"⏭️ 冷却中 ({last_status})", "count": len(cached_nodes), "fail_count": fail_count, "advice": "读取历史缓存"})

    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    return all_raw_nodes, plugin_reports

def generate_dashboard(raw_count, unique_count, alive_count, clash_count, region_counters, plugin_reports):
    dead_scripts = [p["name"] for p in plugin_reports if p["fail_count"] >= MAX_FAIL_STREAK]
    lines = [
        "# 🚀 节点聚合中心 - 实时健康看板",
        f"> **最后更新时间（北京时间）**：`{get_beijing_time()}`\n",
        "## 📊 核心数据汇总",
        "| 统计指标 | 数量 | 说明 |", "| :--- | :--- | :--- |",
        f"| **📥 原始抓取总数** | `{raw_count} 条` | 所有脚本产出的未去重总和 |",
        f"| **🔍 指纹深度去重** | `{unique_count} 条` | 剔除不同源重复节点后的数量 |",
        f"| **🎯 真连接测速存活** | **`{alive_count} 条`** | 严格剔除超时及 0ms 的无效假节点 |",
        f"| **⚔️ Clash 转换成功** | **`{clash_count} 条`** | 最终写入 `clash.yaml` (支持 VLESS Reality / Hy2) |", ""
    ]
    if dead_scripts:
        lines.append("## 🚨 失效脚本下架提醒（重点关注！）")
        lines.append(f"⚠️ 检测到以下 **{len(dead_scripts)}** 个脚本已连续失败满 {MAX_FAIL_STREAK} 次，系统已自动清空其旧缓存，请前往公开库 `plugins/` 目录检查或删除：")
        for ds in dead_scripts: lines.append(f"- ❌ **`plugins/{ds}`** *(建议删除)*")
        lines.append("")
    lines.append("## 🧩 插件脚本健康度明细")
    lines.append("| 脚本名称 | 设定周期 | 当前状态 | 贡献节点数 | 连续失败 | 诊断建议 |")
    lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    for p in plugin_reports:
        lines.append(f"| `{p['name']}` | {p['interval']} | {p['status']} | **{p['count']}** 条 | {p['fail_count']} 次 | {p['advice']} |")
    lines.append("")
    if region_counters:
        lines.append("## 🌍 存活节点地区分布")
        lines.append(" 、 ".join([f"**{k}**: `{v}条`" for k, v in sorted(region_counters.items(), key=lambda x: x[1], reverse=True)]))
        lines.append("")
    report_md = "\n".join(lines)

    with open(os.path.join(VAULT_DIR, "README.md"), "w", encoding="utf-8") as f: f.write(report_md)
    if summary_env := os.environ.get("GITHUB_STEP_SUMMARY"):
        try:
            with open(summary_env, "a", encoding="utf-8") as f: f.write(report_md + "\n")
        except Exception: pass
    print("\n" + "=" * 60)
    print(f"📊 【本次聚合战报】 原始:{raw_count} -> 去重:{unique_count} -> 测速存活:{alive_count} -> Clash:{clash_count}")
    if dead_scripts: print(f"🚨 【下架警告】 以下脚本已连续失效，建议从 plugins/ 中删除: {', '.join(dead_scripts)}")
    else: print("✅ 【脚本健康】 所有启用中的脚本状态均正常！")
    print("=" * 60 + "\n")

def deduplicate_and_speedtest(raw_nodes, plugin_reports):
    unique_map = {}
    for uri in raw_nodes:
        if fp := get_node_fingerprint(uri):
            if fp not in unique_map: unique_map[fp] = uri
    unique_nodes = list(unique_map.values())
    print(f"🔍 汇总总数: {len(raw_nodes)} | 指纹深度去重后: {len(unique_nodes)} 条")

    unique_nodes = filter_dead_pairs(unique_nodes)
    if not unique_nodes:
        generate_dashboard(len(raw_nodes), 0, 0, 0, {}, plugin_reports)
        return

    with open(PRE_TEST_FILE, "w", encoding="utf-8") as f: f.write("\n".join(unique_nodes))

    alive_nodes = []
    if os.path.exists("./lite"):
        print("⚡ 启动内核级真连接测速 (通过 Cloudflare generate_204 验证真实转发)...")
        # 用 googleping：lite 内部走 https://cp.cloudflare.com/generate_204 测【真实代理转发】，
        # 而不是 tcping（只测端口开，会把"端口开但代理已失效"的假活节点混进来）。
        # 实测发现：lite 的 gotping id 从 0 开始，且存活节点多数只有 lost=0% 但没有 ping 数值。
        # 因此存活判定改用 lost < 100%（凡丢包率不足 100% 即视为连通可用），而不是只看 ping>0。
        lite_conf = {
            "group": "MyAggregator", "speedtestMode": "pingonly", "pingMethod": "googleping",
            "sortMethod": "rspeed", "concurrency": 10, "testMode": 2,
            "subscription": PRE_TEST_FILE, "timeout": 3, "language": "en",
            "unique": True, "outputMode": 0,
            "url": "https://cp.cloudflare.com/generate_204"
        }
        with open("lite_config.json", "w", encoding="utf-8") as f: json.dump(lite_conf, f)

        try:
            proc = subprocess.run(["./lite", "-config", "lite_config.json", "-test", PRE_TEST_FILE], capture_output=True, text=True, timeout=720)
            # lite 把 gotping 进度写到 stderr（不是 stdout），必须两个都扫，否则解析不到任何存活
            stdout_log = (proc.stdout or "") + (proc.stderr or "")

            # 存每个存活 id -> 延迟（用于排序；没延迟的 lost=0 也算连通）
            uniq_map = {}
            for line in stdout_log.splitlines():
                if '"info":"gotping"' in line and "{" in line:
                    try:
                        s = line[line.find("{"):]
                        data = json.loads(s)
                        i = int(data["id"])            # lite id 从 0 开始，直接对齐，绝不 -1
                        lost_str = str(data.get("lost", "100%")).replace("%", "")
                        try: lost = float(lost_str)
                        except: lost = 100.0
                        ping_val = data.get("ping")
                        if isinstance(ping_val, (int, float)):
                            # 有明确延迟：超过阈值(默认1000ms)则判定为大卡/死节点，剔除
                            if ping_val <= MAX_LATENCY_MS:
                                uniq_map[i] = ping_val
                            # else: 延迟 > 阈值，丢弃（不加入存活）
                        elif lost < 100:
                            uniq_map.setdefault(i, 999999)  # 连通但未报 ping，也算存活（大延迟占位）
                    except Exception:
                        pass

            # 静态 IP 节点优先：ip 直连比动态域名(vip/3dns等)稳；再按延迟低→高
            _STATIC_RE = __import__("re").compile(r"^\d+\.\d+\.\d+\.\d+$")
            def _rank(idx):
                uri = unique_nodes[idx] if 0 <= idx < len(unique_nodes) else ""
                host = ""
                if "://" in uri:
                    try:
                        host = uri.split("//", 1)[1].split("@", 1)[-1].split(":", 1)[0]
                    except Exception:
                        host = ""
                is_ip = bool(_STATIC_RE.match(host))  # 纯 IPv4 = 静态，优先
                return (0 if is_ip else 1, uniq_map.get(idx, 999999))
            valid_ids = sorted(uniq_map.keys(), key=_rank)
            print(f"✅ 存活节点 {len(valid_ids)} 个（阈值≤{MAX_LATENCY_MS}ms + 静态IP优先）")

            for idx in valid_ids:
                if 0 <= idx < len(unique_nodes):
                    alive_nodes.append(unique_nodes[idx])

        except Exception as e:
            print(f"⚠️ 测速组件运行或解析异常: {e}")

    if not alive_nodes:
        print("ℹ️ 测速过滤后无节点存活，将降级使用去重列表保底...")
        alive_nodes = unique_nodes
    else:
        print(f"🎯 真连接测速完成！精准拦截死节点，存活真节点: {len(alive_nodes)} / {len(unique_nodes)} 条")

    region_counters, final_nodes = {}, []
    for uri in alive_nodes:
        orig_name = extract_original_name(uri)
        region_flag = detect_region_flag(orig_name)
        region_counters[region_flag] = region_counters.get(region_flag, 0) + 1
        final_nodes.append(apply_new_node_name(uri, f"{region_flag} {region_counters[region_flag]:02d} | {orig_name}"))

    with open(os.path.join(VAULT_DIR, "nodes_plain.txt"), "w", encoding="utf-8") as f: f.write("\n".join(final_nodes))
    b64_str = base64.b64encode("\n".join(final_nodes).encode("utf-8")).decode("utf-8")
    with open(os.path.join(VAULT_DIR, "sub_base64.txt"), "w", encoding="utf-8") as f: f.write(b64_str)

    clash_count = export_clash_yaml(final_nodes, os.path.join(VAULT_DIR, "clash.yaml"))
    egern_count = export_egern_yaml(final_nodes, os.path.join(VAULT_DIR, "egern.yaml"))
    singbox_count = export_singbox_json(final_nodes, os.path.join(VAULT_DIR, "sing-box.json"))
    surge_count = export_surge_ini(final_nodes, os.path.join(VAULT_DIR, "surge.conf"))
    wula_count = export_wula_only(final_nodes, os.path.join(VAULT_DIR, "wula.txt"),
                                  os.path.join(VAULT_DIR, "wula_base64.txt"))
    
    if gist_url := upload_to_gist_backup(b64_str):
        report_note = f"\n> 🔗 gist 备份订阅：`{gist_url}`\n"
        with open(os.path.join(VAULT_DIR, "README.md"), "a", encoding="utf-8") as f: f.write(report_note)
        if summary_env := os.environ.get("GITHUB_STEP_SUMMARY"):
            try:
                with open(summary_env, "a", encoding="utf-8") as f: f.write(report_note)
            except Exception: pass

    generate_dashboard(len(raw_nodes), len(unique_nodes), len(final_nodes), clash_count, region_counters, plugin_reports)

if __name__ == "__main__":
    raw, reports = run_plugins_with_cache()
    deduplicate_and_speedtest(raw, reports)
