#!/usr/bin/env python3
"""
boot_proxy.py — GitHub Actions 自举代理
出口来源：私有库 vault_repo/clash.yaml（上次跑出来的池子）
          → 兜底：直接拉线上订阅端点
用途：让 wula.py 等被 Actions 机房 IP 拉黑的插件，走真实节点出口

用法：
    python boot_proxy.py                 # 生成配置并后台启动，写 /tmp/boot_proxy_url
    python boot_proxy.py --port 7890
    python boot_proxy.py --stop          # 停止

成功时把 URL 写到 /tmp/boot_proxy_url（供 shell 读取），exit 0；失败 exit 1。
"""
import argparse
import os
import random
import shutil
import subprocess
import sys
import time
import urllib.parse

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.join(HERE, "vault_repo")
CONF = "/tmp/boot_proxy.yaml"
LOG = "/tmp/boot_proxy.log"
URL_FILE = "/tmp/boot_proxy_url"
PID_FILE = "/tmp/boot_proxy.pid"

# 只挑能过 anytls/vless 的现代客户端类型
KEEP_TYPES = ("anytls", "vless", "vmess", "trojan", "hysteria2", "ss")
# 订阅端点兜底：vault_repo/clash.yaml 缺失或全挂时用
FALLBACK_SUBS = [
    "https://sub.jax.sryze.cc/jax/clash",
]

POOL_MAX = 24          # 池子最大节点数
PROBE_TIMEOUT = 20     # 单节点探测超时
PROBE_URL = "https://www.gstatic.com/generate_204"


class _Dumper(yaml.Dumper):
    """强制所有字符串带引号：reality short-id 这类数字开头 hex
    不加引号会被 yaml 解析成 int，mihomo 直接拒收整份配置。"""


def _qrep(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="'")


class _QStr(str):
    pass


_Dumper.add_representer(_QStr, _qrep)


def _quote_strings(obj):
    """递归把字符串转成带引号的子类（只用于 dump，不做类型判断）。"""
    if isinstance(obj, dict):
        return {k: _quote_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_quote_strings(v) for v in obj]
    if isinstance(obj, str) and obj != "":
        return _QStr(obj)
    return obj


def log(msg):
    print(f"[boot_proxy] {msg}", flush=True)


def load_pool():
    """从 vault_repo/clash.yaml 拿节点；失败则拉线上订阅兜底。"""
    pool = []
    local = os.path.join(VAULT, "clash.yaml")
    if os.path.exists(local):
        try:
            with open(local, "r", encoding="utf-8", errors="ignore") as f:
                data = yaml.safe_load(f) or {}
            pool = data.get("proxies") or []
            log(f"本地池子 vault_repo/clash.yaml → {len(pool)} 条")
        except Exception as e:
            log(f"读本地 clash.yaml 失败: {e}")

    if len(pool) < 5:
        import urllib.request
        for url in FALLBACK_SUBS:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "clash.meta"})
                with urllib.request.urlopen(req, timeout=30) as r:
                    data = yaml.safe_load(r.read().decode("utf-8", "ignore")) or {}
                got = data.get("proxies") or []
                if got:
                    log(f"线上兜底 {url} → {len(got)} 条")
                    pool = got + pool
                    break
            except Exception as e:
                log(f"线上兜底失败 {url}: {e}")

    clean = []
    for p in pool:
        if not isinstance(p, dict):
            continue
        t = p.get("type")
        if t not in KEEP_TYPES:
            continue
        if not p.get("server") or not p.get("port"):
            continue
        # 名字里的单引号会破坏我们强制引号的 dump，先清掉
        name = str(p.get("name") or "").replace("'", "")
        if not name:
            name = f"{t}-{p['server']}"
        p = dict(p)
        p["name"] = name
        clean.append(p)
    return clean


def build_config(pool, port):
    random.shuffle(pool)
    pick = pool[:POOL_MAX]
    if not pick:
        return None
    tags = [p["name"] for p in pick]
    cfg = {
        "mixed-port": port,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "warning",
        "proxies": pick,
        "proxy-groups": [
            {
                "name": "AUTO",
                "type": "url-test",
                "proxies": tags,
                "url": PROBE_URL,
                "interval": 60,
                "tolerance": 100,
            },
            {
                "name": "FALLBACK",
                "type": "fallback",
                "proxies": ["AUTO"] + tags,
                "url": PROBE_URL,
                "interval": 60,
            },
        ],
        "rules": ["MATCH,FALLBACK"],
    }
    return cfg


def stop_existing():
    if os.path.exists(PID_FILE):
        try:
            pid = int(open(PID_FILE).read().strip())
            os.kill(pid, 15)
            log(f"已停止旧进程 pid={pid}")
            time.sleep(1)
        except Exception:
            pass
        try:
            os.remove(PID_FILE)
        except Exception:
            pass


def find_mihomo():
    for cand in ("/usr/local/bin/mihomo", os.path.join(HERE, "mihomo"), "mihomo"):
        path = shutil.which(cand) if os.sep not in cand else cand
        if path and os.path.exists(path):
            return path
    return None


def probe_ok(binary, conf_path):
    """用 mihomo -t 校验配置语法（这是踩过坑的必做步骤）。"""
    r = subprocess.run([binary, "-t", "-f", conf_path], capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    if "test is successful" in out:
        return True
    log(f"配置校验失败:\n{out[-800:]}")
    return False


def wait_ready(port, timeout=25):
    """等 mixed-port 真的能代理出去。"""
    import urllib.request
    op = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}",
                                     "https": f"http://127.0.0.1:{port}"})
    )
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with op.open(PROBE_URL, timeout=PROBE_TIMEOUT) as r:
                if r.status in (200, 204):
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7890)
    ap.add_argument("--stop", action="store_true")
    args = ap.parse_args()

    if args.stop:
        stop_existing()
        return 0

    binary = find_mihomo()
    if not binary:
        log("找不到 mihomo 二进制，跳过自举（插件将直连）")
        return 1

    pool = load_pool()
    log(f"可用节点池: {len(pool)} 条")
    if not pool:
        log("池子为空，跳过自举")
        return 1

    cfg = build_config(pool, args.port)
    if not cfg:
        return 1

    with open(CONF, "w", encoding="utf-8") as f:
        yaml.dump(_quote_strings(cfg), f, Dumper=_Dumper, allow_unicode=True,
                  sort_keys=False, default_flow_style=False)

    if not probe_ok(binary, CONF):
        # 引号方案失败时的兜底：不加引号再来一次
        log("带引号配置被拒，回退裸 dump")
        with open(CONF, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        if not probe_ok(binary, CONF):
            return 1

    stop_existing()
    logf = open(LOG, "w")
    proc = subprocess.Popen([binary, "-f", CONF], stdout=logf, stderr=logf,
                            start_new_session=True)
    with open(PID_FILE, "w") as f:
        f.write(str(proc.pid))
    log(f"mihomo 已启动 pid={proc.pid} port={args.port}")

    if not wait_ready(args.port):
        log("代理端口未就绪（节点可能全挂），停止自举")
        stop_existing()
        return 1

    url = f"http://127.0.0.1:{args.port}"
    with open(URL_FILE, "w") as f:
        f.write(url)
    log(f"✅ 自举代理就绪: {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
