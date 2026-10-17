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

def get_beijing_time():
    """获取北京时间字符串"""
    tz_bj = timezone(timedelta(hours=8))
    return datetime.now(tz_bj).strftime("%Y-%m-%d %H:%M:%S")

def parse_interval(py_path):
    """读取 py 文件前 5 行的 # @interval: 标记，返回秒数（默认 50m）"""
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
    """尝试 Base64 解码"""
    s = s.strip()
    if not s or len(s) < 16 or " " in s:
        return None
    try:
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return None

def quote_safe(s):
    return quote(s)

def clash_proxy_to_uri(p):
    """将 Clash YAML 中的单个 proxy 字典转换为标准节点 URI 以便统一管理"""
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

def extract_nodes_from_text(content):
    """万用提取器：支持明文、Base64订阅、Clash YAML 混杂提取"""
    nodes = []
    content = content.strip()
    if not content:
        return nodes

    if "proxies:" in content:
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
                for p in data["proxies"]:
                    uri = clash_proxy_to_uri(p)
                    if uri: nodes.append(uri)
                if nodes: return nodes
        except Exception:
            pass

    decoded = try_b64_decode(content)
    if decoded and any(scheme in decoded for scheme in VALID_SCHEMES):
        content = decoded

    for line in content.splitlines():
        line = line.strip()
        if line.startswith(VALID_SCHEMES):
            nodes.append(line)
        else:
            sub_dec = try_b64_decode(line)
            if sub_dec:
                for sub_line in sub_dec.splitlines():
                    if sub_line.strip().startswith(VALID_SCHEMES):
                        nodes.append(sub_line.strip())
    return nodes

def get_node_fingerprint(uri):
    """计算节点的唯一底层指纹（忽略节点名称，按 协议+服务器+端口+密码/UUID 去重）"""
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
    """提取节点的原始备注名称"""
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

def detect_region_flag(raw_name):
    """根据原节点名称识别国家/地区国旗前缀"""
    name = raw_name.upper()
    if any(x in name for x in ["HK", "香港", "HONGKONG", "HONG KONG"]): return "🇭🇰 香港"
    if any(x in name for x in ["TW", "台湾", "台灣", "TAIWAN", "TAIPEI", "TPE"]): return "🇹🇼 台湾"
    if any(x in name for x in ["JP", "日本", "JAPAN", "TOKYO", "TYO", "OSAKA", "KIX", "NRT"]): return "🇯🇵 日本"
    if any(x in name for x in ["SG", "新加坡", "SINGAPORE", "狮城", "SIN"]): return "🇸🇬 新加坡"
    if any(x in name for x in ["US", "美国", "美國", "AMERICA", "UNITED STATES", "LAX", "SJC", "SEA", "NYC", "ORD"]): return "🇺🇸 美国"
    if any(x in name for x in ["KR", "韩国", "韓國", "KOREA", "SEOUL", "ICN"]): return "🇰🇷 韩国"
    if any(x in name for x in ["UK", "GB", "英国", "英國", "ENGLAND", "LONDON", "LHR"]): return "🇬🇧 英国"
    if any(x in name for x in ["DE", "德国", "德國", "GERMANY", "FRA", "FRANKFURT"]): return "🇩🇪 德国"
    if any(x in name for x in ["FR", "法国", "法國", "FRANCE", "PARIS", "CDG"]): return "🇫🇷 法国"
    if any(x in name for x in ["CA", "加拿大", "CANADA", "YVR", "YYZ"]): return "🇨🇦 加拿大"
    if any(x in name for x in ["AU", "澳大利亚", "澳洲", "AUSTRALIA", "SYD", "MEL"]): return "🇦🇺 澳大利亚"
    if any(x in name for x in ["RU", "俄罗斯", "俄羅斯", "RUSSIA", "MOW"]): return "🇷🇺 俄罗斯"
    if any(x in name for x in ["IN", "印度", "INDIA", "BOM"]): return "🇮🇳 印度"
    if any(x in name for x in ["NL", "荷兰", "荷蘭", "NETHERLANDS", "AMS"]): return "🇳🇱 荷兰"
    if any(x in name for x in ["TR", "土耳其", "TURKEY", "IST"]): return "🇹🇷 土耳其"
    if any(x in name for x in ["TH", "泰国", "泰國", "THAILAND", "BKK"]): return "🇹🇭 泰国"
    if any(x in name for x in ["VN", "越南", "VIETNAM", "SGN", "HAN"]): return "🇻🇳 越南"
    if any(x in name for x in ["MY", "马来西亚", "馬來西亞", "MALAYSIA", "KUL"]): return "🇲🇾 马来西亚"
    if any(x in name for x in ["PH", "菲律宾", "菲律賓", "PHILIPPINES", "MNL"]): return "🇵🇭 菲律宾"
    if any(x in name for x in ["ID", "印尼", "印度尼西亚", "INDONESIA", "CGK"]): return "🇮🇩 印尼"
    if any(x in name for x in ["BR", "巴西", "BRAZIL", "GRU"]): return "🇧🇷 巴西"
    if any(x in name for x in ["ZA", "南非", "SOUTH AFRICA", "JNB"]): return "🇿🇦 南非"
    return "🌐 其它"

def apply_new_node_name(uri, new_name):
    """将格式化后的新名称写回节点"""
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

def uri_to_clash_proxy(uri):
    """将标准 URI 转换为支持 Mihomo/Clash.Meta 的 Proxy 字典 (支持 VLESS Reality / Hy2)"""
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
    """原生生成支持 Mihomo / Clash.Meta 的 clash.yaml 配置文件"""
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
            {"name": "⚡ 自动优选", "type": "url-test", " proxies": proxy_names, "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50},
            {"name": "🔯 故障转移", "type": "fallback", "proxies": proxy_names, "url": "http://www.gstatic.com/generate_204", "interval": 300}
        ],
        "rules": [
            "GEOIP,LAN,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择"
        ]
    }
    # 修正键名空格
    clash_Wait["proxy-groups"][1]["proxies"] = proxy_names
    clash_Wait["proxy-groups"][1].pop(" proxies", None)

    with open(out_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(clash_Wait, f, allow_unicode=True, sort_keys=False)
    return len(proxies)

def run_plugins_with_cache():
    """核心分频调度器 + 脚本失效监控"""
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

    # 自动清理已经在 plugins 目录被你手动删除的脚本缓存记录
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
    """生成可视化统计看板（同时写入私有库 README.md 与 GitHub Actions Summary）"""
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

    # 1. 写入私有库 README.md，打开私有库主页直接可见
    with open(os.path.join(VAULT_DIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(report_md)

    # 2. 写入 GitHub Actions 官方 Summary 面板
    summary_env = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_env:
        try:
            with open(summary_env, "a", encoding="utf-8") as f:
                f.write(report_md + "\n")
        except Exception:
            pass

    # 3. 在控制台打印精简尾声汇总
    print("\n" + "=" * 60)
    print(f"📊 【本次聚合战报】 原始:{raw_count} -> 去重:{unique_count} -> 测速存活:{alive_count} -> Clash:{clash_count}")
    if dead_scripts:
        print(f"🚨 【下架警告】 以下脚本已连续失效，建议从 plugins/ 中删除: {', '.join(dead_scripts)}")
    else:
        print("✅ 【脚本健康】 所有启用中的脚本状态均正常！")
    print("=" * 60 + "\n")

def deduplicate_and_speedtest(raw_nodes, plugin_reports):
    """指纹去重 + 调用内核进行真连接测速 + 导出成品与看板"""
    unique_map = {}
    for uri in raw_nodes:
        fp = get_node_fingerprint(uri)
        if fp not in unique_map:
            unique_map[fp] = uri

    unique_nodes = list(unique_map.values())
    print(f"🔍 汇总总数: {len(raw_nodes)} | 指纹深度去重后: {len(unique_nodes)} 条")

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

    # 智能归类国家国旗 + 保留原节点备注
    region_counters = {}
    final_nodes = []
    for uri in alive_nodes:
        orig_name = extract_original_name(uri)
        region_flag = detect_region_flag(orig_name)
        region_counters[region_flag] = region_counters.get(region_flag, 0) + 1
        seq = region_counters[region_flag]
        
        new_label = f"{region_flag} {seq:02d} | {orig_name}"
        final_nodes.append(apply_new_node_name(uri, new_label))

    # 导出 1：明文列表 (nodes_plain.txt)
    with open(os.path.join(VAULT_DIR, "nodes_plain.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(final_nodes))

    # 导出 2：通用 Base64 订阅 (sub_base64.txt)
    b64_str = base64.b64encode("\n".join(final_nodes).encode("utf-8")).decode("utf-8")
    with open(os.path.join(VAULT_DIR, "sub_base64.txt"), "w", encoding="utf-8") as f:
        f.write(b64_str)

    # 导出 3：原生生成 Clash Meta 配置文件 (clash.yaml)
    clash_count = export_clash_yaml(final_nodes, os.path.join(VAULT_DIR, "clash.yaml"))

    # 生成可视化监控看板
    generate_dashboard(len(raw_nodes), len(unique_nodes), len(final_nodes), clash_count, region_counters, plugin_reports)

if __name__ == "__main__":
    raw, reports = run_plugins_with_cache()
    deduplicate_and_speedtest(raw, reports)
