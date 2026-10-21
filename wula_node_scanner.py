#!/usr/bin/env python3
"""
wula_node_scanner.py — 扫描节点池，挑出能打开乌拉官网的节点

输出（写入 vault_repo/，会随第 6 步推送到私有库）：
    wula_pool.json   {"updated": "...", "source_ip": ["a","b"], "nodes": {名字: 节点配置}}

用法：
    python wula_node_scanner.py                 # 扫描（默认最多 120 条、并发 16）
    python wula_node_scanner.py --limit 60      # 限制扫描数量
    python wula_node_scanner.py --list          # 只看当前池子内容

设计要点：
    * 每个节点单独起一个 mihomo 实例（8090+index 端口），互不干扰
    * 判定标准：能拿到 wula001.com 的任意 HTTP 响应（200/302/403 都算通，
      403 说明 WAF 看到了请求，节点本身是通的；只有连接层失败才算死）
    * 并发跑，单节点超时 12s，整体可控
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.join(HERE, "vault_repo")
POOL_FILE = os.path.join(VAULT, "wula_pool.json")
# @interval: 6h  —— 节点池每 6 小时重扫一次，避免在下次更新前失效
DEFAULT_INTERVAL = 6 * 3600
PROBE = "https://wula001.com/"
BASE_PORT = 18000
PER_NODE_TIMEOUT = 12
MAX_WORKERS = 16
CHALLENGE_PATH = "/fd0fb2130e/challenge"
DEFAULT_BUDGET = 900      # 默认时间预算（秒），到点就停，扫多少算多少

KEEP_TYPES = ("anytls", "vless", "vmess", "trojan", "hysteria2", "ss")


# ---------- YAML 引号保护（reality short-id 数字开头 hex 必须加引号） ----------
class _Dumper(yaml.Dumper):
    pass


class _QStr(str):
    pass


def _qrep(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="'")


_Dumper.add_representer(_QStr, _qrep)


def _quote_strings(obj):
    if isinstance(obj, dict):
        return {k: _quote_strings(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_quote_strings(v) for v in obj]
    if isinstance(obj, str) and obj != "":
        return _QStr(obj)
    return obj


def log(msg):
    print(f"[scanner] {msg}", flush=True)


# ---------- 出口IP烧名单（与 plugins/wula.py 同格式、同位置 vault_repo/wula_burn.json） ----------
BURN_DECAY_H = int(os.environ.get("WULA_BURN_DECAY_H", "24"))


def _burn_path():
    return os.path.join(VAULT, "wula_burn.json")


def _load_burn():
    try:
        with open(_burn_path(), encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def mark_burn(egress, why=""):
    """出口 IP 在 deep 测试网络层失败 → 记入烧名单（wula 在 24h 内跳过该出口）。"""
    if not egress:
        return
    with threading.Lock():
        b = _load_burn()
        v = b.get(egress) or {"ts": 0, "fails": 0}
        v["fails"] = int(v.get("fails", 0)) + 1
        v["ts"] = time.time()
        if why:
            v["last_err"] = str(why)[:80]
        b[egress] = v
        try:
            with open(_burn_path(), "w", encoding="utf-8") as f:
                json.dump(b, f, ensure_ascii=False, indent=1)
        except Exception as e:
            log(f"烧名单落盘失败: {e}")


def _pool_age_ok(interval):
    """池子是否仍在有效期内。返回 (ok, 已过秒数, 总条数)。"""
    if not os.path.exists(POOL_FILE):
        return False, 0, 0
    try:
        data = json.load(open(POOL_FILE, encoding="utf-8"))
    except Exception:
        return False, 0, 0
    ts = data.get("ts") or 0
    if not ts:
        try:
            ts = os.path.getmtime(POOL_FILE)
        except Exception:
            ts = 0
    age = time.time() - ts if ts else 10 ** 9
    return age < interval, age, len(data.get("nodes") or {})


def find_mihomo():
    for cand in ("/usr/local/bin/mihomo", os.path.join(HERE, "mihomo"), "mihomo"):
        path = shutil.which(cand) if os.sep not in cand else cand
        if path and os.path.exists(path):
            return path
    return None


def load_pool():
    """节点池来源优先级：vault_repo/clash.yaml → 线上订阅"""
    pool = []
    local = os.path.join(VAULT, "clash.yaml")
    if os.path.exists(local):
        try:
            with open(local, "r", encoding="utf-8", errors="ignore") as f:
                data = yaml.safe_load(f) or {}
            pool = data.get("proxies") or []
            log(f"本地池子 vault_repo/clash.yaml → {len(pool)} 条")
        except Exception as e:
            log(f"读本地池子失败: {e}")

    if len(pool) < 5:
        try:
            req = urllib.request.Request(
                "https://sub.jax.sryze.cc/jax/clash",
                headers={"User-Agent": "clash.meta"})
            with urllib.request.urlopen(req, timeout=40) as r:
                data = yaml.safe_load(r.read().decode("utf-8", "ignore")) or {}
            got = data.get("proxies") or []
            if got:
                log(f"线上兜底 → {len(got)} 条")
                pool = got + pool
        except Exception as e:
            log(f"线上兜底失败: {e}")

    clean = []
    seen = set()
    for p in pool:
        if not isinstance(p, dict):
            continue
        if p.get("type") not in KEEP_TYPES:
            continue
        if not p.get("server") or not p.get("port"):
            continue
        name = str(p.get("name") or "").replace("'", "")
        if not name:
            name = f"{p['type']}-{p['server']}"
        key = (p["type"], p["server"], p["port"], name)
        if key in seen:
            continue
        seen.add(key)
        p = dict(p)
        p["name"] = name
        clean.append(p)
    return clean


def test_node(mihomo, proxy, port, target=PROBE, deep=False):
    """单节点测试：起独立 mihomo，探出口IP，试连 target。

    返回 (ok, verdict, egress)
      egress: 该节点出口 IP（探测失败为 None）——写进池子供 wula 做烧名单
      deep=False：连接层通过即 ok（拿到任何 HTTP 响应，含 403/404）
      deep=True ：打 challenge 接口要 token（能过 WAF）
    """
    p_node = {k: v for k, v in proxy.items() if k not in ("egress", "exit_ip")}
    cfg = {
        "mixed-port": port,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "silent",
        "proxies": [p_node],
        "proxy-groups": [{"name": "G", "type": "select", "proxies": [p_node["name"]]}],
        "rules": ["MATCH,G"],
    }
    fd, conf_path = tempfile.mkstemp(suffix=".yaml", prefix="wscan_")
    os.close(fd)
    try:
        with open(conf_path, "w", encoding="utf-8") as f:
            yaml.dump(_quote_strings(cfg), f, Dumper=_Dumper,
                      allow_unicode=True, sort_keys=False)
        proc = subprocess.Popen([mihomo, "-f", conf_path],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                start_new_session=True)
        try:
            time.sleep(1.0)  # 等端口起来
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({
                "http": f"http://127.0.0.1:{port}",
                "https": f"http://127.0.0.1:{port}",
            }))
            # 先探出口 IP（wula 侧烧名单按出口 IP 粒度，池子也要标注）
            egress = None
            try:
                with opener.open("https://api.ipify.org", timeout=PER_NODE_TIMEOUT) as r:
                    egress = (r.read(64).decode().strip() or None)
            except Exception:
                egress = None
            if deep:
                # 深测：直接打 wula 的 challenge 接口，看是否被风控软拒
                base = target.rstrip("/") if target.startswith("http") else PROBE.rstrip("/")
                req = urllib.request.Request(
                    base + CHALLENGE_PATH,
                    data=b"{}",
                    headers={"Content-Type": "application/json",
                             "User-Agent": "Mozilla/5.0",
                             "accept": "application/json"},
                    method="POST")
                try:
                    with opener.open(req, timeout=PER_NODE_TIMEOUT) as r:
                        body = r.read(4000)
                    j = json.loads(body.decode("utf-8", "ignore"))
                    if j.get("token") and j.get("challenge"):
                        return True, "CHAL-OK", egress
                    return False, "CHAL-BAD", egress
                except urllib.error.HTTPError as e:
                    return False, f"CHAL-HTTP{e.code}", egress
                except Exception as e:
                    return False, f"CHAL-{type(e).__name__}", egress
            try:
                r = opener.open(target, timeout=PER_NODE_TIMEOUT)
                try:
                    r.read(128)
                except Exception:
                    pass
                return True, f"HTTP{r.status}", egress
            except urllib.error.HTTPError as e:
                # 拿到 HTTP 响应 = 连接层通（403 WAF 也算节点可达）
                return True, f"HTTP{e.code}", egress
            except Exception as e:
                return False, type(e).__name__, egress
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    finally:
        try:
            os.remove(conf_path)
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0,
                    help="最多扫描几条（0=全部，默认全部）")
    ap.add_argument("--workers", type=int, default=MAX_WORKERS)
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET,
                    help="时间预算秒数，到点停止（默认900，0=不限）")
    ap.add_argument("--interval", type=float, default=6,
                    help="最小扫描间隔（小时，默认6；0=每次必扫）")
    ap.add_argument("--force", action="store_true", help="强制重扫（忽略间隔）")
    ap.add_argument("--list", action="store_true", help="只列当前池子")
    ap.add_argument("--target", default=PROBE, help="探测目标 URL")
    ap.add_argument("--deep", action="store_true",
                    help="深测：还要求 challenge 接口返回合法 token（能真正注册）")
    ap.add_argument("--keep", action="store_true",
                    help="与旧池子合并（默认覆盖）")
    args = ap.parse_args()

    os.makedirs(VAULT, exist_ok=True)

    if args.list:
        if os.path.exists(POOL_FILE):
            data = json.load(open(POOL_FILE))
            nodes = data.get("nodes", {})
            log(f"当前池子 {len(nodes)} 条（更新于 {data.get('updated','?')}）")
            for n in list(nodes)[:50]:
                print(f"  · {n}")
        else:
            log("池子文件不存在")
        return 0

    # 定时机制：池子未过期且不为空时直接跳过（--force 可强制重扫）
    interval = args.interval * 3600 if args.interval > 0 else DEFAULT_INTERVAL
    if not args.force:
        fresh, age, cnt = _pool_age_ok(interval)
        if fresh and cnt > 0:
            log(f"⏭️ 池子仍有效（{cnt} 条，{age/3600:.1f}h 前扫的，"
                f"间隔 {interval//3600}h），跳过本轮。--force 可强制重扫")
            return 0

    mihomo = find_mihomo()
    if not mihomo:
        log("❌ 找不到 mihomo 二进制")
        return 1
    log(f"mihomo: {mihomo}")

    pool = load_pool()
    if not pool:
        log("❌ 节点池为空")
        return 1

    # 优先扫历史成功节点（快速命中），再扫新的
    old_nodes = {}
    if args.keep and os.path.exists(POOL_FILE):
        try:
            old_nodes = json.load(open(POOL_FILE)).get("nodes", {})
        except Exception:
            pass

    candidates = pool if args.limit <= 0 else pool[:args.limit]
    log(f"待扫描 {len(candidates)}/{len(pool)} 条，并发 {args.workers}，"
        f"预算 {args.budget}s，目标 {args.target}")

    good = {}
    lock = threading.Lock()
    t0 = time.time()
    deadline = (t0 + args.budget) if args.budget > 0 else None
    scanned_count = [0]

    def worker(idx_proxy):
        idx, proxy = idx_proxy
        if deadline and time.time() > deadline:
            return False
        port = BASE_PORT + (idx % 500)
        ok, verdict, egress = test_node(mihomo, proxy, port, args.target, args.deep)
        with lock:
            scanned_count[0] += 1
            mark = "✅" if ok else "❌"
            eg_txt = f" 出口{egress}" if egress else ""
            print(f"  {mark} [{idx:3d}] {verdict:10s} {proxy['name'][:42]}{eg_txt}", flush=True)
        if ok:
            with lock:
                good[proxy["name"]] = {**proxy, "egress": egress}
        elif (args.deep and egress and verdict.startswith("CHAL-")
              and not verdict.startswith("CHAL-BAD")
              and not verdict.startswith("CHAL-HTTP")):
            # challenge 在网络层挂掉 = 这个出口在 wula 那里不受欢迎（或节点死）→ 烧名单
            mark_burn(egress, verdict)
        return ok

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(worker, enumerate(candidates)))

    elapsed = time.time() - t0
    if old_nodes:
        merged = {**old_nodes, **good}
    else:
        merged = good

    # 出口 IP（用第一个可用节点确认）
    out = {
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ts": int(time.time()),
        "target": args.target,
        "deep": bool(args.deep),
        "scanned": scanned_count[0],
        "candidates": len(candidates),
        "budget_hit": bool(deadline and time.time() > deadline),
        "alive": len(good),
        "nodes": merged,
    }
    with open(POOL_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    log(f"扫描完成: {len(good)}/{scanned_count[0]} 可用（候选 {len(candidates)}），用时 {elapsed:.0f}s")
    log(f"已写入 {POOL_FILE}（累计 {len(merged)} 条）")
    return 0 if good else 2


if __name__ == "__main__":
    sys.exit(main())
