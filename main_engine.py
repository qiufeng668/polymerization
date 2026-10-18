# main_engine.py
import os
import re
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
VAULT_DIR = "vault_repo"          # 私有库挂载目录
STATE_FILE = os.path.join(VAULT_DIR, "cache_state.json")
SANDBOX_DIR = "temp_sandbox"      # 脚本隔离运行沙盒
PRE_TEST_FILE = "pre_test_nodes.txt"

# 连续失败多少次提示下架并清空旧缓存
MAX_FAIL_STREAK = 3

VALID_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://", "hysteria://", "hysteria2://", "hy2://", "tuic://", "wg://")

# 插件文件名(去 .py) → 节点名来源前缀
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
    except Exception as e:
        print(f"⚠️ 读取 {py_path} 头部标签异常: {e}")
    return default_sec

def format_interval(sec):
    if sec % 86400 == 0: return f"{sec // 86400}天"
    if sec % 3600 == 0: return f"{sec // 3600}小时"
    return f"{sec // 60}分钟"

def try_b64_decode(s):
    s = s.strip()
    if not s:
        return None
    s = re.sub(r'[\s\r\n]+', '', s)
    if len(s) < 8:
        return None
    try:
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        dec = base64.b64decode(s, validate=False)
        text = dec.decode('utf-8', errors='ignore')
        if text and all(ord(c) >= 32 or c in '\r\n\t' for c in text):
            return text
    except Exception:
        pass
    try:
        s2 = s.replace('-', '+').replace('_', '/')
        missing_padding = len(s2) % 4
        if missing_padding:
            s2 += '=' * (4 - missing_padding)
        dec = base64.b64decode(s2)
        text = dec.decode('utf-8', errors='ignore')
        if text and all(ord(c) >= 32 or c in '\r\n\t' for c in text):
            return text
    except Exception:
        pass
    return None


def quote_safe(s):
    return quote(s)


def clash_proxy_to_uri(p):
    try:
        ptype = p.get("type", "").lower()
        name = quote_safe(str(p.get("name", "Clash_Node")))
        server = p.get("server", "")
        port = p.get("port", "")
        if not server or not port:
            return None
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
            b64 = base64.b64encode(json.dumps(v_json).encode()).decode()
            return f"vmess://{b64}"
        elif ptype == "vless":
            uuid = p.get("uuid", "")
            tls = "tls" if p.get("tls") else "none"
            sni = p.get("servername", "")
            net = p.get("network", "tcp")
            return f"vless://{uuid}@{server}:{port}?security={tls}&type={net}&sni={sni}#{name}"
        elif ptype == "trojan":
            pwd = p.get("password", "")
            sni = p.get("sni", "")
            return f"trojan://{pwd}@{server}:{port}?sni={sni}#{name}"
        elif ptype == "ss":
            cipher = p.get("cipher", "aes-256-gcm")
            pwd = p.get("password", "")
            userinfo = base64.urlsafe_b64encode(f"{cipher}:{pwd}".encode()).decode().rstrip("=")
            return f"ss://{userinfo}@{server}:{port}#{name}"
        elif ptype in ("hysteria2", "hy2"):
            pwd = p.get("password", "")
            sni = p.get("sni", "")
            return f"hysteria2://{pwd}@{server}:{port}?sni={sni}&insecure=1#{name}"
    except Exception:
        pass
    return None


def _contains_scheme(text):
    return any(sch in text for sch in VALID_SCHEMES)


def _deep_extract(content, depth=0):
    if depth > 3:
        return []
    content = content.strip()
    if not content:
        return []
    nodes, seen = [], set()
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(VALID_SCHEMES):
            if line not in seen:
                seen.add(line)
                nodes.append(line)
            continue
        sub_dec = try_b64_decode(line)
        if sub_dec:
            inner = _deep_extract(sub_dec, depth + 1)
            for n in inner:
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
    if not content:
        return nodes

    yaml_nodes = []
    if "proxies:" in content:
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
                for p in data["proxies"]:
                    uri = clash_proxy_to_uri(p)
                    if uri:
                        yaml_nodes.append(uri)
        except Exception:
            pass

    text_nodes = _deep_extract(content, 0)

    seen = set()
    merged = []
    for n in yaml_nodes + text_nodes:
        if n not in seen:
            seen.add(n)
            merged.append(n)
    return merged

def get_node_fingerprint(uri):
    try:
        if uri.startswith("vmess://"):
            b64 = uri[8:].split("#")[0]
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            key = f"vmess://{data.get('add')}:{data.get('port')}:{data.get('id')}:{data.get('path','')}"
            return hashlib.md5(key.encode()).hexdigest()
        else:
            core = uri.split("#")[0]
            return hashlib.md5(core.encode()).hexdigest()
    except Exception:
        return hashlib.md5(uri.encode()).hexdigest()

def extract_original_name(uri):
    try:
        if uri.startswith("vmess://"):
            b64 = uri[8:].split("#")[0].strip()
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            ps = str(data.get("ps", "")).strip()
            if ps:
                return unquote(ps)
        if "#" in uri:
            return unquote(uri.split("#", 1)[1]).strip()
    except Exception:
        pass
    return "未命名节点"

DEAD_UUID = "00000000-0000-0000-0000-000000000000"
BAD_HOSTS = {"127.0.0.1", "0.0.0.0", "localhost", "::1"}
BAD_PORTS = {"0", "1"}
_RE_HOST_PORT = re.compile(r'^[a-z0-9]+://[^@/]+@([^:/?#]+):(\d+)')


def filter_dead_pairs(nodes):
    import re
    out, dropped = [], 0
    for link in nodes:
        base = link.split("#", 1)[0].lower()
        bad = False
        if DEAD_UUID in base:
            bad = True
        else:
            m = re.match(_RE_HOST_PORT, base)
            if m and (m.group(1) in BAD_HOSTS or m.group(2) in BAD_PORTS):
                bad = True
        if bad:
            dropped += 1
        else:
            out.append(link)
    if dropped:
        print(f"🧹 死节点参数级预筛：剔除 {dropped} 个（全零uuid/回环地址/无效端口）")
    return out

def detect_region_flag(raw_name):
    if not raw_name:
        return "🌐 其它"
    name = raw_name
    upper = name.upper()

    for city, flag in DETECT_CITY:
        if city in name:
            return flag

    for kw, flag in DETECT_CN:
        if kw in name:
            return flag

    import re as _re
    m = _re.findall(r'[\U0001F1E6-\U0001F1FF]{2}', name)
    for emoji in m:
        cc = chr(ord(emoji[0]) - 0x1F1E6 + 65) + chr(ord(emoji[1]) - 0x1F1E6 + 65)
        if cc in DETECT_CC_BY_CODE:
            return DETECT_CC_BY_CODE[cc]

    import re as _re2
    toks = set(_re2.split(r'[^A-Za-z0-9]+', upper))
    for cc in sorted(toks & set(DETECT_CC_BY_CODE)):
        return DETECT_CC_BY_CODE[cc]

    if any(k in upper for k in ("自动", "AUTO", "LOADBALANCE", "负载均衡", "随机", "BEST")):
        return "🌐 自动"

    return "🌐 其它"


_DETECT_CITY_RAW = [
    ("东京", "🇯🇵 东京"), ("大阪", "🇯🇵 大阪"), ("名古屋", "🇯🇵 名古屋"), ("札幌", "🇯🇵 札幌"),
    ("福冈", "🇯🇵 福冈"), ("横滨", "🇯🇵 横滨"), ("埼玉", "🇯🇵 埼玉"), ("TOKYO", "🇯🇵 东京"),
    ("OSAKA", "🇯🇵 大阪"), ("NAGOYA", "🇯🇵 名古屋"), ("NRT", "🇯🇵 东京"), ("KIX", "🇯🇵 大阪"), ("TYO", "🇯🇵 东京"),
    ("首尔", "🇰🇷 首尔"), ("釜山", "🇰🇷 釜山"), ("仁川", "🇰🇷 仁川"),
    ("SEOUL", "🇰🇷 首尔"), ("ICN", "🇰🇷 首尔"), ("BUSAN", "🇰🇷 釜山"),
    ("台北", "🇹🇼 台北"), ("新北", "🇹🇼 新北"), ("高雄", "🇹🇼 高雄"), ("台中", "🇹🇼 台中"),
    ("台南", "🇹🇼 台南"), ("TAIPEI", "🇹🇼 台北"), ("TPE", "🇹🇼 台北"),
    ("新加坡", "🇸🇬 新加坡"), ("狮城", "🇸🇬 新加坡"), ("SINGAPORE", "🇸🇬 新加坡"), ("SIN", "🇸🇬 新加坡"),
    ("雅加达", "🇮🇩 雅加达"), ("JAKARTA", "🇮🇩 雅加达"), ("CGK", "🇮🇩 雅加达"),
    ("吉隆坡", "🇲🇾 吉隆坡"), ("KUALA", "🇲🇾 吉隆坡"), ("KUL", "🇲🇾 吉隆坡"),
    ("曼谷", "🇹🇭 曼谷"), ("BANGKOK", "🇹🇭 曼谷"), ("BKK", "🇹🇭 曼谷"),
    ("马尼拉", "🇵🇭 马尼拉"), ("MANILA", "🇵🇭 马尼拉"), ("MNL", "🇵🇭 马尼拉"),
    ("河内", "🇻🇳 河内"), ("胡志明", "🇻🇳 胡志明"), ("HANOI", "🇻🇳 河内"), ("HCM", "🇻🇳 胡志明"),
    ("孟买", "🇮🇳 孟买"), ("班加罗尔", "🇮🇳 班加罗尔"), ("新德里", "🇮🇳 新德里"), ("金奈", "🇮🇳 金奈"),
    ("达卡", "🇧🇩 达卡"), ("MUMBAI", "🇮🇳 孟买"), ("BOM", "🇮🇳 孟买"), ("BLR", "🇮🇳 班加罗尔"), ("DELHI", "🇮🇳 新德里"),
    ("迪拜", "🇦🇪 迪拜"), ("阿布扎比", "🇦🇪 阿布扎比"), ("DUBAI", "🇦🇪 迪拜"),
    ("伊斯坦布尔", "🇹🇷 伊斯坦布尔"), ("IST", "🇹🇷 伊斯坦布尔"),
    ("法兰克福", "🇩🇪 法兰克福"), ("柏林", "🇩🇪 柏林"), ("慕尼黑", "🇩🇪 慕尼黑"),
    ("FRANKFURT", "🇩🇪 法兰克福"), ("FRA", "🇩🇪 法兰克福"), ("BERLIN", "🇩🇪 柏林"),
    ("巴黎", "🇫🇷 巴黎"), ("马赛", "🇫🇷 马赛"), ("PARIS", "🇫🇷 巴黎"), ("CDG", "🇫🇷 巴黎"),
    ("伦敦", "🇬🇧 伦敦"), ("曼彻斯特", "🇬🇧 曼彻斯特"), ("LONDON", "🇬🇧 伦敦"), ("LHR", "🇬🇧 伦敦"),
    ("阿姆斯特丹", "🇳🇱 阿姆斯特丹"), ("AMS", "🇳🇱 阿姆斯特丹"),
    ("苏黎世", "🇨🇭 苏黎世"), ("日内瓦", "🇨🇭 日内瓦"),
    ("马德里", "🇪🇸 马德里"), ("巴塞罗那", "🇪🇸 巴塞罗那"),
    ("米兰", "🇮🇹 米兰"), ("罗马", "🇮🇹 罗马"),
    ("华沙", "🇵🇱 华沙"), ("斯德哥尔摩", "🇸🇪 斯德哥尔摩"), ("赫尔辛基", "🇫🇮 赫尔辛基"),
    ("维也纳", "🇦🇹 维也纳"), ("布拉格", "🇨🇿 布拉格"), ("布达佩斯", "🇭🇺 布达佩斯"),
    ("莫斯科", "🇷🇺 莫斯科"), ("圣彼得堡", "🇷🇺 圣彼得堡"), ("MOW", "🇷🇺 莫斯科"),
    ("多伦多", "🇨🇦 多伦多"), ("温哥华", "🇨🇦 温哥华"), ("蒙特利尔", "🇨🇦 蒙特利尔"), ("卡尔加里", "🇨🇦 卡尔加里"),
    ("TORONTO", "🇨🇦 多伦多"), ("YVR", "🇨🇦 温哥华"), ("YYZ", "🇨🇦 多伦多"),
    ("洛杉矶", "🇺🇸 洛杉矶"), ("圣克拉拉", "🇺🇸 圣克拉拉"), ("圣何塞", "🇺🇸 圣何塞"),
    ("西雅图", "🇺🇸 西雅图"), ("达拉斯", "🇺🇸 达拉斯"), ("纽约", "🇺🇸 纽约"), ("芝加哥", "🇺🇸 芝加哥"),
    ("凤凰城", "🇺🇸 凤凰城"), ("迈阿密", "🇺🇸 迈阿密"), ("硅谷", "🇺🇸 硅谷"), ("拉斯维加斯", "🇺🇸 拉斯维加斯"),
    ("LAX", "🇺🇸 洛杉矶"), ("SEA", "🇺🇸 西雅图"), ("NYC", "🇺🇸 纽约"), ("SJC", "🇺🇸 圣何塞"), ("ORD", "🇺🇸 芝加哥"),
    ("圣保罗", "🇧🇷 圣保罗"), ("里约", "🇧🇷 里约"), ("SAO", "🇧🇷 圣保罗"), ("GRU", "🇧🇷 圣保罗"),
    ("布宜诺斯艾利斯", "🇦🇷 布宜诺斯艾利斯"),
    ("悉尼", "🇦🇺 悉尼"), ("墨尔本", "🇦🇺 墨尔本"), ("SYD", "🇦🇺 悉尼"), ("MEL", "🇦🇺 墨尔本"),
    ("奥克兰", "🇳🇿 奥克兰"), ("约翰内斯堡", "🇿🇦 约翰内斯堡"), ("开普敦", "🇿🇦 开普敦"), ("JNB", "🇿🇦 约翰内斯堡"),
]
DETECT_CITY = sorted(_DETECT_CITY_RAW, key=lambda x: -len(x[0]))

_DETECT_CN_RAW = [
    ("印度尼西亚", "🇮🇩 印尼"), ("印度尼西亞", "🇮🇩 印尼"), ("印度尼西亚", "🇮🇩 印尼"),
    ("澳大利亚", "🇦🇺 澳大利亚"), ("澳洲", "🇦🇺 澳大利亚"), ("台灣", "🇹🇼 台湾"), ("台湾", "🇹🇼 台湾"),
    ("香港", "🇭🇰 香港"), ("HONGKONG", "🇭🇰 香港"), ("HONG KONG", "🇭🇰 香港"), ("新加坡", "🇸🇬 新加坡"), ("SINGAPORE", "🇸🇬 新加坡"), ("SIN", "🇸🇬 新加坡"),
    ("日本", "🇯🇵 日本"), ("JAPAN", "🇯🇵 日本"), ("韩国", "🇰🇷 韩国"), ("韓國", "🇰🇷 韩国"), ("KOREA", "🇰🇷 韩国"), ("美国", "🇺🇸 美国"), ("美國", "🇺🇸 美国"), ("AMERICA", "🇺🇸 美国"), ("UNITED STATES", "🇺🇸 美国"), ("英国", "🇬🇧 英国"), ("英國", "🇬🇧 英国"), ("ENGLAND", "🇬🇧 英国"), ("德国", "🇩🇪 德国"), ("德國", "🇩🇪 德国"), ("GERMANY", "🇩🇪 德国"), ("法国", "🇫🇷 法国"), ("法國", "🇫🇷 法国"), ("FRANCE", "🇫🇷 法国"), ("加拿大", "🇨🇦 加拿大"), ("CANADA", "🇨🇦 加拿大"), ("澳大利亚", "🇦🇺 澳大利亚"), ("AUSTRALIA", "🇦🇺 澳大利亚"), ("俄罗斯", "🇷🇺 俄罗斯"), ("俄羅斯", "🇷🇺 俄罗斯"), ("RUSSIA", "🇷🇺 俄罗斯"), ("印度", "🇮🇳 印度"), ("INDIA", "🇮🇳 印度"), ("荷兰", "🇳🇱 荷兰"), ("荷蘭", "🇳🇱 荷兰"), ("NETHERLANDS", "🇳🇱 荷兰"), ("土耳其", "🇹🇷 土耳其"), ("TURKEY", "🇹🇷 土耳其"), ("泰国", "🇹🇭 泰国"), ("泰國", "🇹🇭 泰国"), ("THAILAND", "🇹🇭 泰国"), ("越南", "🇻🇳 越南"), ("VIETNAM", "🇻🇳 越南"), ("马来西亚", "🇲🇾 马来西亚"), ("馬來西亞", "🇲🇾 马来西亚"), ("MALAYSIA", "🇲🇾 马来西亚"), ("菲律宾", "🇵🇭 菲律宾"), ("菲律賓", "🇵🇭 菲律宾"), ("PHILIPPINES", "🇵🇭 菲律宾"), ("印尼", "🇮🇩 印尼"), ("INDONESIA", "🇮🇩 印尼"), ("巴西", "🇧🇷 巴西"), ("BRAZIL", "🇧🇷 巴西"), ("南非", "🇿🇦 南非"), ("SOUTH AFRICA", "🇿🇦 南非"), ("新西兰", "🇳🇿 新西兰"), ("紐西蘭", "🇳🇿 新西兰"),
    ("意大利", "🇮🇹 意大利"), ("ITALY", "🇮🇹 意大利"), ("西班牙", "🇪🇸 西班牙"), ("SPAIN", "🇪🇸 西班牙"), ("瑞士", "🇨🇭 瑞士"), ("SWITZERLAND", "🇨🇭 瑞士"), ("瑞典", "🇸🇪 瑞典"), ("SWEDEN", "🇸🇪 瑞典"), ("波兰", "🇵🇱 波兰"), ("POLAND", "🇵🇱 波兰"), ("阿联酋", "🇦🇪 阿联酋"), ("UAE", "🇦🇪 阿联酋"), ("埃及", "🇪🇬 埃及"), ("EGYPT", "🇪🇬 埃及"), ("阿根廷", "🇦🇷 阿根廷"), ("ARGENTINA", "🇦🇷 阿根廷"), ("智利", "🇨🇱 智利"), ("CHILE", "🇨🇱 智利"), ("墨西哥", "🇲🇽 墨西哥"), ("MEXICO", "🇲🇽 墨西哥"), ("比利时", "🇧🇪 比利时"), ("BELGIUM", "🇧🇪 比利时"), ("奥地利", "🇦🇹 奥地利"), ("AUSTRIA", "🇦🇹 奥地利"), ("丹麦", "🇩🇰 丹麦"), ("DENMARK", "🇩🇰 丹麦"), ("芬兰", "🇫🇮 芬兰"), ("FINLAND", "🇫🇮 芬兰"), ("挪威", "🇳🇴 挪威"), ("NORWAY", "🇳🇴 挪威"), ("捷克", "🇨🇿 捷克"), ("CZECH", "🇨🇿 捷克"), ]
DETECT_CN = sorted(_DETECT_CN_RAW, key=lambda x: -len(x[0]))

DETECT_CC_BY_CODE = {}
for _cc, _flag in [
    ("HK", "🇭🇰 香港"), ("TW", "🇹🇼 台湾"), ("JP", "🇯🇵 日本"), ("KP", "🇰🇵 朝鲜"), ("KR", "🇰🇷 韩国"),
    ("SG", "🇸🇬 新加坡"), ("US", "🇺🇸 美国"), ("GB", "🇬🇧 英国"), ("UK", "🇬🇧 英国"), ("DE", "🇩🇪 德国"),
    ("FR", "🇫🇷 法国"), ("CA", "🇨🇦 加拿大"), ("AU", "🇦🇺 澳大利亚"), ("RU", "🇷🇺 俄罗斯"),
    ("IN", "🇮🇳 印度"), ("NL", "🇳🇱 荷兰"), ("TR", "🇹🇷 土耳其"), ("TH", "🇹🇭 泰国"),
    ("VN", "🇻🇳 越南"), ("MY", "🇲🇾 马来西亚"), ("PH", "🇵🇭 菲律宾"), ("ID", "🇮🇩 印尼"),
    ("BR", "🇧🇷 巴西"), ("ZA", "🇿🇦 南非"), ("NZ", "🇳🇿 新西兰"), ("IT", "🇮🇹 意大利"),
    ("ES", "🇪🇸 西班牙"), ("CH", "🇨🇭 瑞士"), ("SE", "🇸🇪 瑞典"), ("PL", "🇵🇱 波兰"),
    ("AE", "🇦🇪 阿联酋"), ("EG", "🇪🇬 埃及"), ("AR", "🇦🇷 阿根廷"), ("CL", "🇨🇱 智利"),
    ("MX", "🇲🇽 墨西哥"), ("BE", "🇧🇪 比利时"), ("AT", "🇦🇹 奥地利"), ("DK", "🇩🇰 丹麦"),
    ("FI", "🇫🇮 芬兰"), ("NO", "🇳🇴 挪威"), ("CZ", "🇨🇿 捷克"), ("HU", "🇭🇺 匈牙利"),
    ("PT", "🇵🇹 葡萄牙"), ("RO", "🇷🇴 罗马尼亚"), ("UA", "🇺🇦 乌克兰"), ("SA", "🇸🇦 沙特"),
    ("IL", "🇮🇱 以色列"), ("QA", "🇶🇦 卡塔尔"), ("PK", "🇵🇰 巴基斯坦"), ("BD", "🇧🇩 孟加拉国"),
]:
    DETECT_CC_BY_CODE[_cc] = _flag

def apply_new_node_name(uri, new_name):
    try:
        if uri.startswith("vmess://"):
            b64 = uri[8:].split("#")[0].strip()
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            data["ps"] = new_name
            new_b64 = base64.b64encode(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}#{quote_safe(new_name)}"
    except Exception:
        pass
    base_part = uri.split("#")[0]
    return f"{base_part}#{quote_safe(new_name)}"


def apply_source_prefix(uri, tag):
    orig = extract_original_name(uri)
    if not orig or orig == "未命名节点":
        orig = tag
    import re as _re
    orig = _re.sub(r'[\U0001F1E6-\U0001F1FF]{2}', '', orig).strip()
    if orig.startswith("|"):
        orig = orig[1:].strip()
    if not orig:
        orig = tag
    if orig.startswith(tag):
        return uri
    new_name = f"{tag}{orig}"
    return apply_new_node_name(uri, new_name)


def uri_to_clash_proxy(uri):
    try:
        name = extract_original_name(uri)
        if uri.startswith("vmess://"):
            b64 = uri[8:].split("#")[0].strip()
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            d = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            proxy = {
                "name": d.get("ps", name),
                "type": "vmess",
                "server": d.get("add"),
                "port": int(d.get("port", 443)),
                "uuid": d.get("id"),
                "alterId": int(d.get("aid", 0)),
                "cipher": d.get("scy", "auto"),
                "udp": True,
                "tls": d.get("tls") == "tls",
                "skip-cert-verify": True,
                "network": d.get("net", "tcp")
            }
            if d.get("sni"): proxy["servername"] = d.get("sni")
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("host", d.get("add", ""))}}
            return proxy

        parsed = urlparse(uri)
        scheme = parsed.scheme.lower()
        server = parsed.hostname
        port = parsed.port or 443
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
                proxy["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": q.get("sid", "")}
            if proxy["network"] == "ws":
                proxy["ws-opts"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", q.get("sni", server))}}
            elif proxy["network"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
            elif proxy["network"] == "xhttp":
                opts = {"path": q.get("path", "/")}
                if q.get("mode"): opts["mode"] = q["mode"]
                proxy["xhttp-opts"] = opts
            return proxy

        elif scheme in ("hysteria2", "hy2"):
            proxy = {
                "name": name, "type": "hysteria2", "server": server, "port": int(port),
                "password": userinfo, "udp": True, "skip-cert-verify": True
            }
            if q.get("sni"): proxy["sni"] = q["sni"]
            if q.get("obfs"):
                proxy["obfs"] = q["obfs"]
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

        elif scheme == "ss":
            if ":" not in userinfo:
                dec = try_b64_decode(userinfo)
                if dec: userinfo = dec
            if ":" in userinfo:
                cipher, pwd = userinfo.split(":", 1)
                return {
                    "name": name, "type": "ss", "server": server, "port": int(port),
                    "cipher": cipher, "password": pwd, "udp": True
                }
    except Exception:
        pass
    return None

def export_clash_yaml(final_nodes, out_path):
    proxies = []
    proxy_names = []
    for uri in final_nodes:
        p = uri_to_clash_proxy(uri)
        if p and p.get("server") and p.get("port"):
            proxies.append(p)
            proxy_names.append(p["name"])

    if not proxies:
        return 0

    clash_Wait = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "unified-delay": True,
        "tcp-concurrent": True,
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "nameserver": ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]
        },
        "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动优选", "🔯 故障转移"] + proxy_names},
            {"name": "⚡ 自动优选", "type": "url-test", "proxies": proxy_names, "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50},
            {"name": "🔯 故障转移", "type": "fallback", "proxies": proxy_names, "url": "http://www.gstatic.com/generate_204", "interval": 300}
        ],
        "rules": [
            "GEOIP,LAN,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择"
        ]
    }
    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(clash_Wait, f, allow_unicode=True, sort_keys=False)
    return len(proxies)

GIST_DESC = "poly-sub-backup"
GIST_FILENAME = "sub_base64.txt"


def upload_to_gist_backup(content):
    import requests as _rq
    token = (os.environ.get("GIST_TOKEN") or "").strip()
    if not token:
        print("ℹ️ 未设置 GIST_TOKEN，跳过 gist 冗余备份")
        return None
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    gist_id = None
    try:
        for page in range(1, 6):
            r = _rq.get("https://api.github.com/gists", headers=headers,
                        params={"per_page": 100, "page": page}, timeout=30)
            if r.status_code != 200:
                break
            for g in r.json():
                if g.get("description") == GIST_DESC and GIST_FILENAME in g.get("files", {}):
                    gist_id = g["id"]
                    break
            if gist_id or len(r.json()) < 100:
                break
        payload = {"description": GIST_DESC, "public": False,
                   "files": {GIST_FILENAME: {"content": content}}}
        if gist_id:
            r = _rq.patch(f"https://api.github.com/gists/{gist_id}", headers=headers, json=payload, timeout=30)
        else:
            r = _rq.post("https://api.github.com/gists", headers=headers, json=payload, timeout=30)
        if r.status_code in (200, 201):
            gid = r.json()["id"]
            raw = f"https://gist.githubusercontent.com/raw/{gid}/{GIST_FILENAME}"
            print(f"💾 gist 冗余备份成功: {raw}")
            return raw
        print(f"⚠️ gist 备份失败: {r.status_code}")
    except Exception as e:
        print(f"⚠️ gist 备份异常: {e}")
    return None


def run_plugins_with_cache():
    os.makedirs(VAULT_DIR, exist_ok=True)
    state = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            state = {}

    now = int(time.time())
    py_files = sorted(glob.glob(os.path.join(PLUGIN_DIR, "*.py")))
    active_script_names = {os.path.basename(p) for p in py_files}

    for old_key in list(state.keys()):
        if old_key not in active_script_names:
            del state[old_key]

    all_raw_nodes = []
    plugin_reports = []

    print(f"📦 共扫描到 {len(py_files)} 个插件脚本")

    for py_path in py_files:
        script_name = os.path.basename(py_path)
        interval_sec = parse_interval(py_path)
        info = state.get(script_name, {})
        last_run = info.get("last_run", 0)
        cached_nodes = info.get("nodes", [])
        if cached_nodes:
            _tag = plugin_tag(script_name)
            cached_nodes = [apply_source_prefix(u, _tag) for u in cached_nodes]
        fail_count = info.get("fail_count", 0)
        elapsed = now - last_run

        if elapsed + 180 >= interval_sec or not cached_nodes:
            print(f"🚀 [执行] {script_name} (设定间隔: {format_interval(interval_sec)}, 历史连续失败: {fail_count}次)")
            
            if os.path.exists(SANDBOX_DIR):
                shutil.rmtree(SANDBOX_DIR)
            os.makedirs(SANDBOX_DIR, exist_ok=True)
            shutil.copy(py_path, os.path.join(SANDBOX_DIR, script_name))
            
            try:
                proc = subprocess.run(
                    ["python", script_name],
                    cwd=SANDBOX_DIR,
                    capture_output=False,
                    text=True,
                    timeout=300
                )
                
                extracted = []
                for root, _, files in os.walk(SANDBOX_DIR):
                    for file in files:
                        if file == script_name or file.endswith(".pyc"):
                            continue
                        fpath = os.path.join(root, file)
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as rf:
                                extracted.extend(extract_nodes_from_text(rf.read()))
                        except Exception:
                            pass

                if extracted:
                    tag = plugin_tag(script_name)
                    extracted = [apply_source_prefix(u, tag) for u in extracted]
                    print(f"   ✅ 成功从 {script_name} 提取到 {len(extracted)} 条节点，已重置失败计数！")
                    state[script_name] = {
                        "last_run": now,
                        "last_success": get_beijing_time(),
                        "fail_count": 0,
                        "nodes": extracted
                    }
                    all_raw_nodes.extend(extracted)
                    plugin_reports.append({
                        "name": script_name,
                        "interval": format_interval(interval_sec),
                        "status": "✅ 正常更新",
                        "count": len(extracted),
                        "fail_count": 0,
                        "advice": "运行良好"
                    })
                else:
                    fail_count += 1
                    print(f"   ⚠️ {script_name} 本次未产出有效节点 (连续失败 {fail_count} 次)")
                    if fail_count >= MAX_FAIL_STREAK:
                        print(f"   🚨 [严重警告] {script_name} 已连续失败 {fail_count} 次，疑似失效！已清空其死节点缓存，建议下架删除！")
                        cached_nodes = []
                    state[script_name] = {
                        "last_run": now,
                        "last_success": info.get("last_success", "从未成功"),
                        "fail_count": fail_count,
                        "nodes": cached_nodes
                    }
                    all_raw_nodes.extend(cached_nodes)
                    plugin_reports.append({
                        "name": script_name,
                        "interval": format_interval(interval_sec),
                        "status": "🚨 疑似失效" if fail_count >= MAX_FAIL_STREAK else "⚠️ 本次空载",
                        "count": len(cached_nodes),
                        "fail_count": fail_count,
                        "advice": "🚨 建议下架删除！" if fail_count >= MAX_FAIL_STREAK else f"沿用旧缓存(失败{fail_count}次)"
                    })
            except Exception as e:
                fail_count += 1
                print(f"   ❌ {script_name} 运行崩溃: {e} (连续失败 {fail_count} 次)")
                if fail_count >= MAX_FAIL_STREAK:
                    cached_nodes = []
                state[script_name] = {
                    "last_run": now,
                    "last_success": info.get("last_success", "从未成功"),
                    "fail_count": fail_count,
                    "nodes": cached_nodes
                }
                all_raw_nodes.extend(cached_nodes)
                plugin_reports.append({
                    "name": script_name,
                    "interval": format_interval(interval_sec),
                    "status": "🚨 脚本崩溃" if fail_count >= MAX_FAIL_STREAK else "❌ 运行报错",
                    "count": len(cached_nodes),
                    "fail_count": fail_count,
                    "advice": "🚨 建议下架删除！" if fail_count >= MAX_FAIL_STREAK else f"超时或报错(失败{fail_count}次)"
                })
        else:
            remain_min = (interval_sec - elapsed) // 60
            print(f"⏭️ [跳过] {script_name} 冷却中 (还需等待 {remain_min} 分钟)，读取缓存 ({len(cached_nodes)} 条)")
            all_raw_nodes.extend(cached_nodes)
            plugin_reports.append({
                "name": script_name,
                "interval": format_interval(interval_sec),
                "status": f"⏭️ 冷却中({remain_min}m)",
                "count": len(cached_nodes),
                "fail_count": fail_count,
                "advice": "🚨 建议下架删除！" if fail_count >= MAX_FAIL_STREAK else "读取历史缓存"
            })

    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

    return all_raw_nodes, plugin_reports

def generate_dashboard(raw_count, unique_count, alive_count, clash_count, region_counters, plugin_reports):
    dead_scripts = [p["name"] for p in plugin_reports if p["fail_count"] >= MAX_FAIL_STREAK]
    
    lines = [
        "# 🚀 节点聚合中心 - 实时健康看板",
        f"> **最后更新时间（北京时间）**：`{get_beijing_time()}`\n",
        "## 📊 核心数据汇总",
        "| 统计指标 | 数量 | 说明 |",
        "| :--- | :--- | :--- |",
        f"| **📥 原始抓取总数** | `{raw_count} 条` | 所有脚本产出的未去重总和 |",
        f"| **🔍 指纹深度去重** | `{unique_count} 条` | 剔除不同源重复节点后的数量 |",
        f"| **🎯 真连接测速存活** | **`{alive_count} 条`** | 最终写入 `nodes_plain.txt` 与 `sub_base64.txt` |",
        f"| **⚔️ Clash 转换成功** | **`{clash_count} 条`** | 最终写入 `clash.yaml` (支持 VLESS Reality / Hy2) |",
        ""
    ]

    if dead_scripts:
        lines.append("## 🚨 失效脚本下架提醒（重点关注！）")
        lines.append(f"⚠️ 检测到以下 **{len(dead_scripts)}** 个脚本已连续失败满 {MAX_FAIL_STREAK} 次，系统已自动清空其旧缓存，请前往公开库 `plugins/` 目录检查或删除：")
        for ds in dead_scripts:
            lines.append(f"- ❌ **`plugins/{ds}`** *(建议删除)*")
        lines.append("")

    lines.append("## 🧩 插件脚本健康度明细")
    lines.append("| 脚本名称 | 设定周期 | 当前状态 | 贡献节点数 | 连续失败 | 诊断建议 |")
    lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    for p in plugin_reports:
        lines.append(f"| `{p['name']}` | {p['interval']} | {p['status']} | **{p['count']}** 条 | {p['fail_count']} 次 | {p['advice']} |")
    lines.append("")

    if region_counters:
        lines.append("## 🌍 存活节点地区分布")
        region_str = " 、 ".join([f"**{k}**: `{v}条`" for k, v in sorted(region_counters.items(), key=lambda x: x[1], reverse=True)])
        lines.append(region_str)
        lines.append("")

    report_md = "\n".join(lines)

    with open(os.path.join(VAULT_DIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(report_md)

    summary_env = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_env:
        try:
            with open(summary_env, "a", encoding="utf-8") as f:
                f.write(report_md + "\n")
        except Exception:
            pass

    print("\n" + "=" * 60)
    print(f"📊 【本次聚合战报】 原始:{raw_count} -> 去重:{unique_count} -> 测速存活:{alive_count} -> Clash:{clash_count}")
    if dead_scripts:
        print(f"🚨 【下架警告】 以下脚本已连续失效，建议从 plugins/ 中删除: {', '.join(dead_scripts)}")
    else:
        print("✅ 【脚本健康】 所有启用中的脚本状态均正常！")
    print("=" * 60 + "\n")

def deduplicate_and_speedtest(raw_nodes, plugin_reports):
    unique_map = {}
    for uri in raw_nodes:
        fp = get_node_fingerprint(uri)
        if fp not in unique_map:
            unique_map[fp] = uri

    unique_nodes = list(unique_map.values())
    print(f"🔍 汇总总数: {len(raw_nodes)} | 指纹深度去重后: {len(unique_nodes)} 条")

    unique_nodes = filter_dead_pairs(unique_nodes)
    print(f"🧪 参数级预筛后剩余: {len(unique_nodes)} 条")

    if not unique_nodes:
        print("⚠️ 没有任何可用节点，终止导出。")
        generate_dashboard(len(raw_nodes), 0, 0, 0, {}, plugin_reports)
        return

    with open(PRE_TEST_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(unique_nodes))

    alive_nodes = []
    if os.path.exists("./lite"):
        print("⚡ 启动内核级真连接测速 (Testing real HTTP latency via proxy)...")
        lite_conf = {
            "group": "MyAggregator",
            "speedtestMode": "pingonly",
            "pingMethod": "googleping",
            "sortMethod": "rspeed",
            "concurrency": 16,
            "testMode": 2,
            "subscription": PRE_TEST_FILE,
            "timeout": 10,
            "language": "en",
            "unique": True,
            "outputMode": 0
        }
        with open("lite_config.json", "w", encoding="utf-8") as f:
            json.dump(lite_conf, f)

        try:
            subprocess.run(["./lite", "-config", "lite_config.json", "-test", PRE_TEST_FILE], timeout=720)
            if os.path.exists("output.txt"):
                with open("output.txt", "r", encoding="utf-8", errors="ignore") as f:
                    alive_nodes = extract_nodes_from_text(f.read())
        except Exception as e:
            print(f"⚠️ 测速组件运行超时或异常，回退使用去重全量列表: {e}")

    if not alive_nodes:
        print("ℹ️ 使用去重后的节点列表进行导出...")
        alive_nodes = unique_nodes
    else:
        print(f"🎯 真连接测速完成！存活真节点: {len(alive_nodes)} / {len(unique_nodes)} 条")

    region_counters = {}
    final_nodes = []
    for uri in alive_nodes:
        orig_name = extract_original_name(uri)
        region_flag = detect_region_flag(orig_name)
        region_counters[region_flag] = region_counters.get(region_flag, 0) + 1
        seq = region_counters[region_flag]
        
        new_label = f"{region_flag} {seq:02d} | {orig_name}"
        final_nodes.append(apply_new_node_name(uri, new_label))

    with open(os.path.join(VAULT_DIR, "nodes_plain.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(final_nodes))

    b64_str = base64.b64encode("\n".join(final_nodes).encode("utf-8")).decode("utf-8")
    with open(os.path.join(VAULT_DIR, "sub_base64.txt"), "w", encoding="utf-8") as f:
        f.write(b64_str)

    clash_count = export_clash_yaml(final_nodes, os.path.join(VAULT_DIR, "clash.yaml"))

    gist_url = upload_to_gist_backup(b64_str)
    if gist_url:
        report_note = f"\n> 🔗 gist 备份订阅：`{gist_url}`\n"
        with open(os.path.join(VAULT_DIR, "README.md"), "a", encoding="utf-8") as f:
            f.write(report_note)
        summary_env = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_env:
            try:
                with open(summary_env, "a", encoding="utf-8") as f:
                    f.write(report_note)
            except Exception:
                pass

    generate_dashboard(len(raw_nodes), len(unique_nodes), len(final_nodes), clash_count, region_counters, plugin_reports)

if __name__ == "__main__":
    raw, reports = run_plugins_with_cache()
    deduplicate_and_speedtest(raw, reports)
