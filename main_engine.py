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
from urllib.parse import urlparse, unquote
import yaml

# 路径配置
PLUGIN_DIR = "plugins"
VAULT_DIR = "vault_repo"          # 私有库挂载目录
STATE_FILE = os.path.join(VAULT_DIR, "cache_state.json")
SANDBOX_DIR = "temp_sandbox"      # 脚本隔离运行沙盒
PRE_TEST_FILE = "pre_test_nodes.txt"
ALIVE_NODES_FILE = "alive_nodes.txt"

VALID_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://", "hysteria://", "hysteria2://", "hy2://", "tuic://", "wg://")

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

def quote_safe(s):
    from urllib.parse import quote
    return quote(s)

def extract_nodes_from_text(content):
    """万用提取器：支持明文、Base64订阅、Clash YAML 混杂提取"""
    nodes = []
    content = content.strip()
    if not content:
        return nodes

    # 1. 尝试作为 Clash YAML 解析
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

    # 2. 尝试整体 Base64 解码
    decoded = try_b64_decode(content)
    if decoded and any(scheme in decoded for scheme in VALID_SCHEMES):
        content = decoded

    # 3. 逐行扫描提取标准协议链接
    for line in content.splitlines():
        line = line.strip()
        if line.startswith(VALID_SCHEMES):
            nodes.append(line)
        else:
            # 兼容单行被 Base64 编码的情况
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

def run_plugins_with_cache():
    """核心分频调度器"""
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
    all_raw_nodes = []

    print(f"📦 共扫描到 {len(py_files)} 个插件脚本")

    for py_path in py_files:
        script_name = os.path.basename(py_path)
        interval_sec = parse_interval(py_path)
        last_run = state.get(script_name, {}).get("last_run", 0)
        cached_nodes = state.get(script_name, {}).get("nodes", [])
        elapsed = now - last_run

        # 判断是否到达设定的冷却时间（预留 180 秒弹性窗口防止 Actions 轻微早到跳过）
        if elapsed + 180 >= interval_sec or not cached_nodes:
            print(f"🚀 [执行] {script_name} (设定间隔: {interval_sec//60}m, 距上次: {elapsed//60}m)")
            
            # 清理并重建沙盒目录
            if os.path.exists(SANDBOX_DIR):
                shutil.rmtree(SANDBOX_DIR)
            os.makedirs(SANDBOX_DIR, exist_ok=True)
            
            # 将脚本复制进沙盒运行，这样它生成的任何文件都在沙盒里
            shutil.copy(py_path, os.path.join(SANDBOX_DIR, script_name))
            
            try:
                proc = subprocess.run(
                    ["python", script_name],
                    cwd=SANDBOX_DIR,
                    capture_output=False,
                    text=True,
                    timeout=300 # 单个脚本最长允许跑 5 分钟
                )
                
                extracted = []
                # 1. 抓取脚本打印到屏幕 (stdout) 的节点
                if proc.stdout:
                    extracted.extend(extract_nodes_from_text(proc.stdout))
                
                # 2. 自动嗅探脚本在目录里生成的所有结果文件
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
                    print(f"   ✅ 成功从 {script_name} 提取到 {len(extracted)} 条节点，已更新缓存！")
                    state[script_name] = {"last_run": now, "nodes": extracted}
                    all_raw_nodes.extend(extracted)
                else:
                    print(f"   ⚠️ {script_name} 本次未产出有效节点，沿用旧缓存 ({len(cached_nodes)} 条)")
                    if proc.stderr:
                        print(f"   [报错日志]: {proc.stderr[:300]}")
                    all_raw_nodes.extend(cached_nodes)
            except Exception as e:
                print(f"   ❌ {script_name} 运行异常: {e}，沿用旧缓存")
                all_raw_nodes.extend(cached_nodes)
        else:
            remain_min = (interval_sec - elapsed) // 60
            print(f"⏭️ [跳过] {script_name} 冷却中 (还需等待 {remain_min} 分钟)，直接读取缓存 ({len(cached_nodes)} 条)")
            all_raw_nodes.extend(cached_nodes)

    # 保存更新后的状态与缓存池回私有库目录
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)

    return all_raw_nodes

def deduplicate_and_speedtest(raw_nodes):
    """指纹去重 + 调用内核进行真连接测速 + 导出成品"""
    unique_map = {}
    for uri in raw_nodes:
        fp = get_node_fingerprint(uri)
        if fp not in unique_map:
            unique_map[fp] = uri

    unique_nodes = list(unique_map.values())
    print(f"🔍 汇总总数: {len(raw_nodes)} | 指纹深度去重后: {len(unique_nodes)} 条")

    if not unique_nodes:
        print("⚠️ 没有任何可用节点，终止导出。")
        return

    with open(PRE_TEST_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(unique_nodes))

    # 调用 Actions 中预装的 LiteSpeedTest 进行真连接测速
    alive_nodes = []
    if os.path.exists("./lite"):
        print("⚡ 启动内核级真连接测速 (Testing real HTTP latency via proxy)...")
        lite_conf = {
            "group": "MyAggregator",
            "speedtestMode": "pingonly", # 仅测试真连接延迟(generate_204)，不跑大流量下载以防耗尽节点流量
            "pingMethod": "googleping",
            "sortMethod": "rspeed",
            "concurrency": 64,
            "testMode": 2,
            "subscription": PRE_TEST_FILE,
            "timeout": 8,
            "language": "en",
            "unique": True,
            "outputMode": 0
        }
        with open("lite_config.json", "w", encoding="utf-8") as f:
            json.dump(lite_conf, f)

        try:
            subprocess.run(["./lite", "-config", "lite_config.json", "-test", PRE_TEST_FILE], timeout=600)
            # 读取测速存活结果
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

    # 统一重命名打标
    final_nodes = []
    for idx, uri in enumerate(alive_nodes, 1):
        base_part = uri.split("#")[0]
        tag = quote_safe(f"⚡ 聚合节点_{idx:03d}")
        final_nodes.append(f"{base_part}#{tag}")

    # 导出 1：明文列表 (nodes.txt)
    with open(os.path.join(VAULT_DIR, "nodes_plain.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(final_nodes))

    # 导出 2：通用 Base64 订阅 (sub_base64.txt)
    b64_str = base64.b64encode("\n".join(final_nodes).encode("utf-8")).decode("utf-8")
    with open(os.path.join(VAULT_DIR, "sub_base64.txt"), "w", encoding="utf-8") as f:
        f.write(b64_str)

    print("🎉 导出文件已成功写入私有库缓存区！")

if __name__ == "__main__":
    raw = run_plugins_with_cache()
    deduplicate_and_speedtest(raw)
