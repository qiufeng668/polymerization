#!/usr/bin/env python3
# @interval: 12h   (Actions 自动跑, 每次注册 1 个账号)
# -*- coding: utf-8 -*-
"""
乌拉VPN：复用有效账号；无有效账号时注册一个，并验证订阅包含有效节点。
原始 PoW / instrumentation 实现：By Jax / Tg by_Jax。
Python 3.11+ | Deps: requests, pyyaml | Build: 无需编译
Run: python3 plugins/wula.py --outdir output
可选: --proxy http://127.0.0.1:7890 --password 自定义密码
WULA_BUDGET_SECONDS 默认480秒；退出码0表示获得节点，2表示失败。
输出 accounts.json、accounts.txt、nodes.txt、nodes.json、clash_all.yaml。
账号及节点认证信息只写结果目录和私库，不打印到公开日志。
"""
import json, time, sys, argparse, hashlib, os, random, string, re, base64, zlib, urllib.parse
# 扫描与注册统一 requests / HTTP/1.1，避免两种 TLS 栈得出矛盾结果。
import requests as _rq
PROXY = None
_DEADLINE = None

class _BudgetExceeded(RuntimeError):
    pass

def _remaining():
    return max(0.0, _DEADLINE - time.monotonic()) if _DEADLINE else 480.0

def _check_budget():
    if _remaining() < 1:
        raise _BudgetExceeded("总时间预算已耗尽")

def _timeout():
    _check_budget()
    return (min(5.0, _remaining()), min(20.0, _remaining()))

def _error_text(ex):
    text = str(ex)
    text = re.sub(r'(?i)((?:token|password|auth_data|recaptcha_data)=)[^&\s\'"<>]+', r'\1[hidden]', text)
    text = re.sub(r'(?i)(https?://)[^/@\s]+:[^/@\s]+@', r'\1[hidden]@', text)
    return text[:240]

def _json_request(s, path, stage, **kwargs):
    try:
        r = s.post(BASE + path, timeout=_timeout(), **kwargs)
        r.raise_for_status()
        value = r.json()
        if not isinstance(value, dict):
            raise ValueError("响应不是 JSON object")
        return value
    except _BudgetExceeded:
        raise
    except Exception as ex:
        raise RuntimeError(f"{stage}: {type(ex).__name__}: {_error_text(ex)}") from None

def _new_session():
    s = _rq.Session()
    # 有显式出口时屏蔽环境代理；否则保留运行环境的标准 HTTPS_PROXY。
    s.trust_env = not bool(PROXY)
    if PROXY:
        s.proxies.update({"http": PROXY, "https": PROXY})
    return s

SUFFIXES = ["gmail.com", "qq.com", "163.com", "126.com", "outlook.com", "hotmail.com", "yahoo.com", "foxmail.com", "sina.com", "yeah.net",
            "sohu.com", "aliyun.com", "139.com", "189.cn", "wo.cn", "vip.qq.com", "vip.163.com", "vip.126.com",
            "21cn.com", "139.com", "5.cn", "tom.com", "yeah.com"]

BASE = "https://wula001.com"
# 提示: 标准库 requests 即可直连, 无需额外依赖
_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

def _rand_ua():
    return random.choice(_UAS)

# ---------------- PoW (Hashcash 验证码求解) ----------------
def _fnv1a(s):
    h = 2166136261
    for c in s:
        h ^= ord(c)
        h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) & 0xFFFFFFFF
    return h

def _xorshift32(x):
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= (x >> 17)
    x ^= (x << 5) & 0xFFFFFFFF
    return x & 0xFFFFFFFF

def _rand_hex(e, t):
    x = _fnv1a(e)
    s = ""
    while len(s) < t:
        x = _xorshift32(x)
        s += format(x, "08x")
    return s[:t]

def _solve_pow(salt, target):
    tb = bytes.fromhex(target) if len(target) % 2 == 0 else bytes.fromhex(target + "0")
    nbytes = len(tb)
    n = 0
    while True:
        if n % 4096 == 0:
            _check_budget()
        if hashlib.sha256((salt + str(n)).encode()).digest()[:nbytes] == tb:
            return n
        n += 1

def _solve_challenge(ch):
    token = ch["token"]
    c, s, d = ch["challenge"]["c"], ch["challenge"]["s"], ch["challenge"]["d"]
    return [_solve_pow(_rand_hex(f"{token}{e}", s), _rand_hex(f"{token}{e}d", d))
            for e in range(1, c + 1)]

# ---------------- instr 指纹 (纯 Python, 无需 node) ----------------
def _i32(x):
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x >= 0x80000000 else x

def _js_mod(a, n):
    return a - n * int(a / n)

def _js_shr(x, k):
    return _i32(x) >> k

def _f(J, u, k):
    return _i32((u ^ J) | (k ^ u))

class _Node:
    __slots__ = ('children', 'parent', 'innerText')
    def __init__(self):
        self.children = []; self.parent = None; self.innerText = ""
    def appendChild(self, c):
        self.children.append(c); c.parent = self; return c
    def removeChild(self, c):
        self.children.remove(c); c.parent = None; return c
    @property
    def lastElementChild(self):
        return self.children[-1]

def _dom(J, c, a):
    root = _Node(); body = _Node(); body.appendChild(root)
    def k(l, j):
        for E in range(8):
            f = _Node(); l.appendChild(f); f.innerText = str(j)
            if (_i32(j) & 1) == 0:
                l = f
            j = _js_shr(j, 1)
        return l
    def N(l, j, v):
        if (l is None) or (l == j):
            return _js_mod(v, 0x100)
        while len(l.children) > 0:
            l.removeChild(l.lastElementChild)
        val = int(l.innerText) if l.innerText else 0
        return N(l.parent, j, _i32(v + val))
    w = N(k(k(k(root, J), c), a), root, 0)
    body.removeChild(root)
    return w

def _replace_iife(seg):
    out = []; i = 0; n = len(seg)
    while i < n:
        if seg.startswith('function(', i):
            brace = seg.index('{', i)
            depth = 0; k = brace
            while k < n:
                if seg[k] == '{': depth += 1
                elif seg[k] == '}':
                    depth -= 1
                    if depth == 0: break
                k += 1
            body = seg[brace + 1:k]
            call = seg.index('(', k + 1)
            depth = 0; m = call
            while m < n:
                if seg[m] == '(': depth += 1
                elif seg[m] == ')':
                    depth -= 1
                    if depth == 0: break
                m += 1
            args = seg[call + 1:m].strip()
            if 'createElement' in body or 'appendChild' in body:
                out.append('__DOM__(%s)' % args)
            else:
                out.append('__F__(%s)' % args)
            i = m + 1
        else:
            out.append(seg[i]); i += 1
    return ''.join(out)

def _split_top(seg):
    parts = []; depth = 0; cur = []
    for ch in seg:
        if ch in '([': depth += 1
        elif ch in ')]': depth -= 1
        if depth == 0 and ch in ',;':
            parts.append(''.join(cur)); cur = []
        else:
            cur.append(ch)
    if cur: parts.append(''.join(cur))
    return [p.strip() for p in parts if p.strip()]

def _eval_expr(rhs, env):
    rhs = rhs.strip()
    m = re.fullmatch(r'\(\((\w+)\^0x([0-9a-f]+)\)&0x7fffffff\)%0x([0-9a-f]+)\+0x([0-9a-f]+)', rhs)
    if m:
        var, x1, mod, add = m.groups()
        v = env[var]
        return _i32(((v ^ int(x1, 16)) & 0x7fffffff) % int(mod, 16) + int(add, 16))
    m = re.fullmatch(r'__F__\((\w+),(\w+),(\w+)\)', rhs)
    if m:
        a, b, c = m.groups()
        return _f(env[a], env[b], env[c])
    m = re.fullmatch(r'__DOM__\((\w+),(\w+),(\w+)\)', rhs)
    if m:
        a, b, c = m.groups()
        return _dom(env[a], env[b], env[c])
    m = re.fullmatch(r'(\w+)([&|^])(\w+)', rhs)
    if m:
        a, op, b = m.groups()
        x, y = env[a], env[b]
        return _i32(x & y if op == '&' else x | y if op == '|' else x ^ y)
    m = re.fullmatch(r'~\((\w+)([&|])(\w+)\)', rhs)
    if m:
        a, op, b = m.groups()
        x, y = env[a], env[b]
        return _i32(~(x & y if op == '&' else x | y))
    m = re.fullmatch(r'(\w+)\^0x([0-9a-f]+)', rhs)
    if m:
        a, c = m.groups()
        return _i32(env[a] ^ int(c, 16))
    m = re.fullmatch(r'(\w+)\^\(0x([0-9a-f]+)\)', rhs)
    if m:
        a, c = m.groups()
        return _i32(env[a] ^ int(c, 16))
    m = re.fullmatch(r'(\w+)', rhs)
    if m and m.group(1) in env:
        return env[m.group(1)]
    raise ValueError('无法求值: ' + rhs)

def _solve_instr(instr_b64):
    js = zlib.decompress(base64.b64decode(instr_b64), -15).decode('utf-8')
    nonce = re.search(r"nonce':'([0-9a-f]+)'", js).group(1)
    vm = re.search(r'var\s+(\w+)=0x([0-9a-f]+),\s*(\w+)=0x([0-9a-f]+),\s*(\w+)=0x([0-9a-f]+),\s*(\w+)=0x([0-9a-f]+);', js)
    vnames = [vm.group(1), vm.group(3), vm.group(5), vm.group(7)]
    vals = [int(vm.group(2), 16), int(vm.group(4), 16), int(vm.group(6), 16), int(vm.group(8), 16)]
    env = dict(zip(vnames, vals))
    start = vm.end()
    rv = re.search(r'var\s+(\w+)=\{\};', js[start:])
    objname = rv.group(1)
    end = start + rv.start()
    seg = js[start:end]
    seg = re.sub(r"navigator\['userAgent'\]\?0x([0-9a-f]+):0x([0-9a-f]+)",
                 lambda mm: '0x' + mm.group(1), seg)
    seg = _replace_iife(seg)
    for stmt in _split_top(seg):
        if '=' not in stmt: continue
        lhs, rhs = stmt.split('=', 1)
        env[lhs.strip()] = _eval_expr(rhs, env)
    fm = re.search(r"return\s+%s\['([a-z0-9]+)'\]=(\w+),%s\['([a-z0-9]+)'\]=(\w+),%s\['([a-z0-9]+)'\]=(\w+),%s\['([a-z0-9]+)'\]=(\w+),%s" % ((objname,) * 5), js)
    fnames = [fm.group(1), fm.group(3), fm.group(5), fm.group(7)]
    fvars = [fm.group(2), fm.group(4), fm.group(6), fm.group(8)]
    state = {}
    for fn, fv in zip(fnames, fvars):
        state[fn] = env[fv]
    return {"i": nonce, "state": state, "ts": int(time.time() * 1000)}

# ---------------- 单账号注册 (防ban版) ----------------
RETRY = 2          # 降低重试, 避免被拉黑后还硬刷
MIN_GAP = 5        # 账号间最小休息秒数
MAX_GAP = 15       # 防ban随机休息上限 (单账号亦适用)

class _Banned(Exception):
    """判定 IP 已被风控拉黑, 立即停止整批"""
    pass

# ---------------- 出口IP烧名单（跨运行持久化, 防止反复鞭尸同一批死IP） ----------------
# 判定: 打 wula 时网络层失败/软拒 的出口 IP 记 1 次; 24h 内不再使用该出口
BURN_DECAY_H = int(os.environ.get("WULA_BURN_DECAY_H", "24"))

def _vault_dir():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.abspath(os.path.join(here, "..", "vault_repo"))
    return p

def _burn_path():
    return os.path.join(_vault_dir(), "wula_burn.json")

def _load_burn():
    p = _burn_path()
    if not os.path.exists(p):
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    expire = time.time() - BURN_DECAY_H * 3600
    return {ip: v for ip, v in (data or {}).items()
            if isinstance(v, dict) and float(v.get("ts", 0) or 0) >= expire}

def _save_burn(b):
    p = _burn_path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(b, f, ensure_ascii=False, indent=1)
    except Exception as e:
        print(f"[!] 烧名单落盘失败: {e}", flush=True)

def _mark_burn(egress, why=""):
    """出口 IP 本次打挂 → 记录。Actions 跨运行共享（vault_repo 会同步私有库）。"""
    if not egress:
        return
    b = _load_burn()
    v = b.get(egress) or {"ts": 0, "fails": 0}
    v["fails"] = int(v.get("fails", 0)) + 1
    v["ts"] = time.time()
    if why:
        v["last_err"] = str(why)[:120]
    expire = time.time() - BURN_DECAY_H * 3600
    b = {k: x for k, x in b.items() if float((x or {}).get("ts", 0) or 0) >= expire}
    b[egress] = v
    _save_burn(b)
    print(f"  🔥 出口 {egress} 记入烧名单 (累计{v['fails']}次, {BURN_DECAY_H}h内不再用)"
          + (f" | {str(why)[:70]}" if why else ""), flush=True)

def _is_burned(egress):
    if not egress:
        return False
    v = _load_burn().get(egress)
    # v1 把 timeout/SSL/邮箱冲突写成封禁；旧记录不再作为跳过依据。
    return bool(v and v.get("confirmed") is True and int(v.get("fails", 0)) >= 1)

# ---------------- 储备账号：新注册全失败时兜底 ----------------
BANK_FALLBACK_ON = os.environ.get("WULA_BANK_FALLBACK", "1") != "0"

def _bank_path():
    return os.path.join(_vault_dir(), "wula_bank.json")

def _save_bank(acc):
    if not acc or not acc.get("token"):
        return
    p = _bank_path()
    bank = []
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                bank = json.load(f)
        except Exception:
            bank = []
    bank = [x for x in bank if isinstance(x, dict) and x.get("token") != acc.get("token")]
    bank.insert(0, {"email": acc.get("email"), "password": acc.get("password"),
                    "token": acc.get("token"), "subscribe_url": acc.get("subscribe_url"),
                    "ts": int(time.time())})
    bank = bank[:10]
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(bank, f, ensure_ascii=False, indent=1)
    except Exception as e:
        print(f"[!] 储备账号落盘失败: {e}", flush=True)

def _use_bank():
    """从储备账号里挑活的拉一次订阅验证。返回 (entry, uris, ytext) 或 None。"""
    p = _bank_path()
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            bank = json.load(f)
    except Exception:
        return None
    for entry in bank[:3]:
        if not isinstance(entry, dict) or _remaining() < 10:
            continue
        token = entry.get("token")
        if not token:
            continue
        try:
            ytext, uris, err = _fetch_nodes(token)
            if not err and uris:
                # 回写时间戳，把这条挪到最新
                try:
                    bank.remove(entry)
                    entry["last_checked"] = int(time.time())
                    bank.insert(0, entry)
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    with open(p, "w", encoding="utf-8") as f:
                        json.dump(bank, f, ensure_ascii=False, indent=1)
                except Exception:
                    pass
                return entry, uris, ytext
        except Exception:
            continue
    return None


def _is_network_block(ex):
    msg = str(ex).lower()
    for kw in ("timed out", "timeout", "connection", "eof", "reset", "refused",
               "unreachable", "ssl", "broken pipe", "connection aborted",
               "read timed out", "recv failure"):
        if kw in msg:
            return True
    return False

def _register_one(email, password):
    last = None
    for attempt in range(1, RETRY + 1):
        _check_budget()
        try:
            time.sleep(random.uniform(0.5, 1.5))
            with _new_session() as s:
                s.headers.update({"User-Agent": _rand_ua(), "referer": BASE + "/",
                                  "origin": BASE, "accept": "application/json"})
                print("    · challenge: 请求验证码...", flush=True)
                ch = _json_request(s, "/fd0fb2130e/challenge", "challenge", json={})
                if not ch.get("token") or not isinstance(ch.get("challenge"), dict) or not ch.get("instrumentation"):
                    raise RuntimeError("challenge: 缺少 token/challenge/instrumentation")
                print(f"    · pow: 计算 {ch['challenge'].get('c', '?')} 题...", flush=True)
                sols = _solve_challenge(ch)
                print("    · instr: 生成指纹...", flush=True)
                try:
                    instr = _solve_instr(ch["instrumentation"])
                except Exception as ex:
                    raise RuntimeError(f"instr: {type(ex).__name__}") from None
                print("    · redeem: 兑换令牌...", flush=True)
                red = _json_request(s, "/fd0fb2130e/redeem", "redeem",
                                    json={"token": ch["token"], "solutions": sols, "instr": instr})
                if not red.get("success") or not red.get("token"):
                    raise RuntimeError("redeem: 验证未通过")
                print("    · register: 提交注册...", flush=True)
                rj = _json_request(s, "/api/v1/passport/auth/register", "register",
                                   data={"email": email, "password": password, "invite_code": "",
                                         "email_code": "", "recaptcha_data": red["token"]})
                data = rj.get("data")
                if not isinstance(data, dict) or not data.get("token"):
                    raise RuntimeError("register: " + _error_text(rj.get("message", "缺少账号 token")))
                token = data["token"]
                return {"email": email, "password": password, "token": token,
                        "auth_data": data.get("auth_data"),
                        "subscribe_url": f"https://windowsv1.com/s/?token={token}"}
        except _BudgetExceeded:
            raise
        except Exception as ex:
            last = ex
            if _is_network_block(ex):
                raise _Banned(_error_text(ex)) from None
            if attempt < RETRY and _remaining() > 10:
                time.sleep(2)
    raise RuntimeError(f"重试{RETRY}次均失败: {_error_text(last)}")

# ---------------- 节点池轮换 (失败换节点重试) ----------------
_NODE_PORT = 7899
_NODE_PROC = None


def _load_node_pool():
    """从 vault_repo/wula_pool.json 读扫描好的可用节点（扫描器产出）。"""
    import json as _json
    cands = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vault_repo", "wula_pool.json"),
        os.path.join(os.getcwd(), "vault_repo", "wula_pool.json"),
        "/tmp/wula_pool.json",
    ]
    for c in cands:
        c = os.path.abspath(c)
        if not os.path.exists(c):
            continue
        try:
            with open(c, "r", encoding="utf-8") as f:
                data = _json.load(f)
            nodes = list((data.get("nodes") or {}).values())
            if nodes:
                print(f"[*] 节点池: {len(nodes)} 条 ({c})", flush=True)
                return nodes
        except Exception as e:
            print(f"[!] 读池子失败 {c}: {e}", flush=True)
    return []


def _auto_scan_pool(budget=None):
    """池子为空时，自己跑一遍扫描器（深测 challenge），把能注册的节点找出来。
    只在被调用时执行，不影响其他插件。"""
    import subprocess as _sp
    scanner = None
    for cand in (os.path.join(os.path.dirname(os.path.abspath(__file__)), "wula_node_scanner.py"),
                 "wula_node_scanner.py",
                 os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wula_node_scanner.py")):
        if os.path.exists(cand):
            scanner = os.path.abspath(cand)
            break
    if not scanner:
        print("[!] 找不到 wula_node_scanner.py，无法自动扫描", flush=True)
        return []
    budget = budget or int(os.environ.get("WULA_SCAN_BUDGET", "600"))
    print(f"[*] 节点池为空，自动扫描（预算 {budget}s）...", flush=True)
    try:
        _sp.run([sys.executable, scanner, "--deep", "--budget", str(budget)],
                timeout=budget + 120, check=False)
    except Exception as e:
        print(f"[!] 自动扫描失败: {e}", flush=True)
    return _load_node_pool()


def _find_mihomo():
    import shutil as _sh
    for cand in ("/usr/local/bin/mihomo", "./mihomo", "mihomo"):
        p = _sh.which(cand) if os.sep not in cand else cand
        if p and os.path.exists(p):
            return p
    return None


def _start_node_proxy(node, attempt):
    """给单个节点起 mihomo，监听 _NODE_PORT。失败返回 False。"""
    global _NODE_PROC
    import subprocess as _sp
    try:
        import yaml as _yaml
    except Exception:
        print("[!] 缺 pyyaml，无法切换节点", flush=True)
        return False

    binary = _find_mihomo()
    if not binary:
        print("[!] 找不到 mihomo，无法切换节点", flush=True)
        return False

    # 停掉上一个
    if _NODE_PROC is not None:
        _kill_proc(_NODE_PROC)
        _NODE_PROC = None

    class _D(_yaml.Dumper):
        pass

    class _Q(str):
        pass

    def _qr(d, x):
        return d.represent_scalar('tag:yaml.org,2002:str', x, style="'")

    _D.add_representer(_Q, _qr)

    def _q(o):
        if isinstance(o, dict):
            return {k: _q(v) for k, v in o.items()}
        if isinstance(o, list):
            return [_q(v) for v in o]
        if isinstance(o, str) and o:
            return _Q(o)
        return o

    # pool 节点带 egress 等扫描元数据, mihomo 不认识 → 剥掉
    p_node = {k: v for k, v in node.items() if k not in ("egress", "exit_ip")}

    cfg = {
        "mixed-port": _NODE_PORT,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "log-level": "silent",
        "proxies": [p_node],
        "proxy-groups": [{"name": "G", "type": "select", "proxies": [p_node["name"]]}],
        "rules": ["MATCH,G"],
    }
    path = f"/tmp/wula_node_{_NODE_PORT}.yaml"
    try:
        with open(path, "w", encoding="utf-8") as f:
            _yaml.dump(_q(cfg), f, Dumper=_D, allow_unicode=True, sort_keys=False)
    except Exception as e:
        print(f"[!] 写节点配置失败: {e}", flush=True)
        return False

    try:
        _NODE_PROC = _sp.Popen([binary, "-f", path],
                               stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                               start_new_session=True)
    except Exception as e:
        print(f"[!] 启动 mihomo 失败: {e}", flush=True)
        return False

    time.sleep(1.2)
    if _NODE_PROC.poll() is not None:
        print(f"[!] 节点进程启动即退出，回退直连: {node['name'][:40]}", flush=True)
        return False
    return True


def _probe_egress(port, timeout=12):
    """用这条代理请求一次出口 IP，验证节点真的通。返回 IP 字符串或 None。"""
    import urllib.request as _ur
    op = _ur.build_opener(_ur.ProxyHandler({
        "http": f"http://127.0.0.1:{port}",
        "https": f"http://127.0.0.1:{port}",
    }))
    try:
        with op.open("https://api.ipify.org", timeout=timeout) as r:
            return r.read().decode().strip() or None
    except Exception:
        return None


def _kill_proc(proc):
    """彻底杀掉 mihomo 及其子进程（它是新会话的组长，要按进程组杀）。"""
    if proc is None:
        return
    import signal as _sig
    try:
        os.killpg(os.getpgid(proc.pid), _sig.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=3)
    except Exception:
        pass


def _stop_node_proxy():
    global _NODE_PROC
    if _NODE_PROC is not None:
        _kill_proc(_NODE_PROC)
        _NODE_PROC = None


def _rand_password(n=12):
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%"]
    pw = [random.choice(p) for p in pools]
    pw += [random.choice(string.ascii_letters + string.digits) for _ in range(n - len(pw))]
    random.shuffle(pw)
    return "".join(pw)

def _rand_email():
    suf = random.choice(SUFFIXES)
    num = random.randint(1000, 99999999)
    letters = "".join(random.choice(string.ascii_lowercase) for _ in range(random.randint(3, 7)))
    return f"{letters}{num}@{suf}"

# ---- 已用邮箱记录：避免反复用同一批邮箱撞车 ----
_USED_EMAILS_FILE = None

def _used_emails_path():
    global _USED_EMAILS_FILE
    if _USED_EMAILS_FILE:
        return _USED_EMAILS_FILE
    cands = ["/tmp/wula_used_emails.txt", os.path.join(os.path.dirname(os.path.abspath(__file__)), "wula_used_emails.txt")]
    for c in cands:
        try:
            d = os.path.dirname(c)
            if d and not os.path.isdir(d):
                continue
            _USED_EMAILS_FILE = c
            return c
        except Exception:
            continue
    _USED_EMAILS_FILE = "/tmp/wula_used_emails.txt"
    return _USED_EMAILS_FILE

def _load_used():
    p = _used_emails_path()
    if not os.path.exists(p):
        return set()
    try:
        with open(p, "r", encoding="utf-8") as f:
            return set(l.strip().lower() for l in f if l.strip())
    except Exception:
        return set()

def _mark_used(email):
    try:
        p = _used_emails_path()
        with open(p, "a", encoding="utf-8") as f:
            f.write(email.lower() + "\n")
    except Exception:
        pass

def _rand_email_unique():
    """生成没在本机用过的邮箱，最多试 200 次。"""
    used = _load_used()
    for _ in range(200):
        e = _rand_email()
        if e.lower() not in used:
            return e
    # 兜底：加时间戳保证唯一
    ts = str(int(time.time() * 1000))[-8:]
    return f"{_rand_email().split('@')[0]}{ts}@{random.choice(SUFFIXES)}"

def _fetch_nodes(token):
    """返回 (Clash YAML, URI列表, 错误)；下载/格式/空节点均视为失败。"""
    import yaml
    yaml_text = None
    last_error = "订阅未下载"
    cfg = None
    for attempt in range(2):
        try:
            with _new_session() as s:
                s.headers.update({"User-Agent": "clash-verge/v1.3.8", "accept": "*/*",
                                  "referer": BASE + "/"})
                r = s.get("https://windowsv1.com/s/", params={"token": token}, timeout=_timeout())
                r.raise_for_status()
                yaml_text = r.text
            cfg = yaml.safe_load(yaml_text)
            if not isinstance(cfg, dict) or not isinstance(cfg.get("proxies"), list):
                raise ValueError("订阅不是包含 proxies 的 Clash YAML")
            break
        except Exception as ex:
            last_error = f"subscription: {type(ex).__name__}: {_error_text(ex)}"
            if attempt == 0 and _remaining() > 5:
                time.sleep(1)
    else:
        return yaml_text, [], last_error
    uris = []
    try:
        for p in cfg.get("proxies", []):
            if not isinstance(p, dict):
                continue
            names = str(p.get("name", ""))
            if any(label in names for label in ("剩余", "到期", "官网", "套餐")):
                continue
            pwd = str(p.get("password", p.get("uuid", "")))
            srv = str(p.get("server", ""))
            try:
                port = int(p.get("port", 0))
            except (ValueError, TypeError):
                continue
            typ = p.get("type", "")
            sni = urllib.parse.quote(str(p.get("sni", p.get("servername", ""))), safe="")
            if not srv or srv.startswith("127.") or srv in ("localhost", "::1", "0.0.0.0") or "$" in names or not 0 < port < 65536 or not pwd:
                continue
            if ":" in srv and not srv.startswith("["):
                srv = f"[{srv}]"
            auth = urllib.parse.quote(pwd, safe="")
            alpn_value = p.get("alpn", [])
            alpn = urllib.parse.quote(",".join(alpn_value) if isinstance(alpn_value, list) else str(alpn_value), safe="")
            extra = f"&alpn={alpn}" if alpn else ""
            if typ in ("hysteria2", "hy2"):
                if p.get("obfs"):
                    extra += "&" + urllib.parse.urlencode({"obfs": p["obfs"], "obfs-password": p.get("obfs-password", "")})
                u = f"hy2://{auth}@{srv}:{port}?sni={sni}&insecure=1{extra}#{urllib.parse.quote(names)}"
            elif typ == "anytls":
                u = (f"anytls://{auth}@{srv}:{port}/?type=tcp&insecure=1"
                     f"&fp={p.get('client-fingerprint','chrome')}&sni={sni}{extra}#{urllib.parse.quote(names)}")
            elif typ == "ss":
                raw = f"{p.get('cipher','aes-128-gcm')}:{pwd}".encode()
                u = (f"ss://{base64.b64encode(raw).decode().rstrip('=')}"
                     f"@{srv}:{port}#{urllib.parse.quote(names)}")
            elif typ == "vless":
                u = (f"vless://{auth}@{srv}:{port}?encryption=none&security=tls"
                     f"&sni={sni}&fp={p.get('client-fingerprint','chrome')}"
                     f"&type={p.get('network','tcp')}#{urllib.parse.quote(names)}")
            elif typ == "trojan":
                u = f"trojan://{auth}@{srv}:{port}?sni={sni}&allowInsecure=1#{urllib.parse.quote(names)}"
            else:
                continue
            uris.append(u)
    except Exception as ex:
        return yaml_text, [], f"订阅解析失败: {type(ex).__name__}"
    if not uris:
        return yaml_text, [], "订阅中没有有效节点"
    return yaml_text, uris, None


def _save_results(accounts, save_dir, nodes_all):
    os.makedirs(save_dir, exist_ok=True)
    txt_path = os.path.join(save_dir, "accounts.txt")
    json_path = os.path.join(save_dir, "accounts.json")
    node_path = os.path.join(save_dir, "nodes.txt")
    node_json_path = os.path.join(save_dir, "nodes.json")
    clash_path = os.path.join(save_dir, "clash_all.yaml")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump([{k: v for k, v in a.items() if not k.startswith("_pre_")} for a in accounts], f, ensure_ascii=False, indent=2)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("========== 乌拉VPN 批量注册结果 ==========\n")
        f.write(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}  成功 {len(accounts)}\n\n")
        for idx, a in enumerate(accounts, 1):
            f.write(f"[{idx}] 邮箱: {a['email']}\n")
            f.write(f"    密码: {a['password']}\n")
            f.write(f"    订阅: {a.get('subscribe_url', '')}\n")
            f.write(f"    节点数: {a.get('node_count', 0)}\n\n")
    # 去重后的节点 URI 列表 (可直接导入所有客户端, 或经订阅转换器生成链接)
    seen = set()
    uniq = []
    for u in nodes_all:
        body = u.split("#")[0]
        if body in seen:
            continue
        seen.add(body)
        uniq.append(u)
    with open(node_path, "w", encoding="utf-8") as f:
        f.write("\n".join(uniq) + "\n")
    with open(node_json_path, "w", encoding="utf-8") as f:
        json.dump([{"uri": u} for u in uniq], f, ensure_ascii=False, indent=2)
    return txt_path, json_path, node_path, len(uniq)

def main():
    global PROXY, _DEADLINE
    PROXY = None
    _DEADLINE = time.monotonic() + max(30, min(540, int(os.environ.get("WULA_BUDGET_SECONDS", "480"))))
    # 优先复用账号；只有没有有效订阅时才创建账号。
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--password", default=None, help="自定义密码 (默认随机)")
    ap.add_argument("--proxy", default=None,
                    help='代理地址, 让脚本和梯子走同一个出口, 例: http://127.0.0.1:7890 或 socks5://127.0.0.1:1080')
    ap.add_argument("--outdir", default=None,
                    help='结果保存目录 (默认自动落到手机 Download)')
    args, _ = ap.parse_known_args()

    if args.proxy is None:
        args.proxy = os.environ.get("WULA_PROXY") or None
    if args.proxy is None:
        # 自举代理：boot_proxy.py 启动成功后会把地址写到这里（Actions 机房 IP 被拉黑时的出路）
        _boot = "/tmp/boot_proxy_url"
        if os.path.exists(_boot):
            try:
                _u = open(_boot).read().strip()
                if _u:
                    args.proxy = _u
                    print("[*] 检测到自举代理（地址不写公开日志）")
            except Exception:
                pass
    if args.proxy:
        PROXY = args.proxy
        print("[*] 已启用显式代理出口（日志隐藏地址）\n")

    accounts = []
    t0 = time.time()
    stopped = False

    # ---------- 轮换节点重试：失败就换，直到成功 ----------
    pool = _load_node_pool()
    initial_proxy = PROXY
    # 先验证配置出口/直连；不在插件的600秒生命周期里再启动长扫描。
    initial_pending = True
    tried = set()
    used_egress = set()
    max_attempts = int(os.environ.get("WULA_MAX_ATTEMPTS", "0")) or (len(pool) + 1 if pool else 1)

    def _pick_node():
        """按 pool 顺序找下一个可用节点：跳过已试名字 / 烧名单出口 / 本轮已用出口。"""
        for n in pool:
            nm = n.get("name")
            if nm in tried:
                continue
            eg = n.get("egress")
            if eg and _is_burned(eg):
                n_fails = int((_load_burn().get(eg) or {}).get("fails", 0))
                print(f"  ⏭️ 出口 {eg} 在烧名单({n_fails}次) → 跳过 {str(nm)[:42]}", flush=True)
                tried.add(nm)
                continue
            if eg and eg in used_egress:
                tried.add(nm)
                continue
            return n
        return None

    acc = None
    bank_used = False
    if BANK_FALLBACK_ON:
        hit = _use_bank()
        if hit:
            entry, pre_uris, pre_ytext = hit
            accounts.append({**{k: v for k, v in entry.items() if k not in ("ts", "last_checked")},
                             "node_count": len(pre_uris), "bank_fallback": True,
                             "_pre_uris": pre_uris, "_pre_ytext": pre_ytext})
            bank_used = True
            print(f"[*] 已复用历史账号并重新下载验证 {len(pre_uris)} 个节点（非新注册）", flush=True)
    real = 0
    guard = 0
    while not accounts and real < max_attempts and guard < 4 * max_attempts + 10:
        if _remaining() < 25:
            print("[*] 总预算接近耗尽，保留时间写入结果", flush=True)
            break
        guard += 1
        args.proxy = None
        PROXY = None
        egress = None
        _stop_node_proxy()
        if initial_pending:
            initial_pending = False
            real += 1
            PROXY = initial_proxy
            args.proxy = initial_proxy
            print(f"\n[{real}/{max_attempts}] 优先验证: {'显式代理' if initial_proxy else '默认网络出口'}", flush=True)
        elif pool:
            node = _pick_node()
            if node is not None:
                tried.add(node.get("name"))
                if _start_node_proxy(node, real + 1):
                    args.proxy = f"http://127.0.0.1:{_NODE_PORT}"
                    PROXY = args.proxy
                    egress = _probe_egress(_NODE_PORT, timeout=5)
                    if egress is None:
                        print("  · 出口IP未知，继续以目标站实际请求判断可用性", flush=True)
                    if _is_burned(egress) or egress in used_egress:
                        print(f"  · 出口 {egress} 已烧/本轮已用 → 跳过 {node['name'][:45]}", flush=True)
                        _stop_node_proxy()
                        continue
                    if egress:
                        used_egress.add(egress)
                    real += 1
                    print(f"\n[{real}/{max_attempts}] 尝试: {node['name'][:45]}  (出口 {egress})", flush=True)
                else:
                    print(f"  · 节点配置无效: {node.get('name','')[:40]}", flush=True)
                    continue
            elif real == 0:
                real += 1
                print(f"\n[{real}/{max_attempts}] 无干净候选 → 直连尝试", flush=True)
            else:
                print("[*] 池子里没有干净出口了，收工", flush=True)
                break
        else:
            print("[*] 没有更多候选出口", flush=True)
            break

        email = _rand_email_unique()
        pwd = args.password or _rand_password()
        try:
            if acc is None:
                acc = _register_one(email, pwd)
                _mark_used(email)
                _save_bank(acc)
            print("    · subscription: 下载并校验节点...", flush=True)
            ytext, uris, err = _fetch_nodes(acc["token"])
            if err or not uris:
                raise RuntimeError(f"注册成功但订阅不可用: {err or '空节点'}")
            acc.update({"_pre_uris": uris, "_pre_ytext": ytext, "node_count": len(uris)})
            accounts.append(acc)
            print(f"  [1/1] OK: 已注册并验证 {len(uris)} 个节点", flush=True)
            break
        except _BudgetExceeded as ex:
            print(f"  ✗ {_error_text(ex)}", flush=True)
            break
        except _Banned as ex:
            print(f"  ✗ 网络层失败: {_error_text(ex)}", flush=True)
            continue
        except Exception as ex:
            print(f"  ✗ {_error_text(ex)}", flush=True)
            time.sleep(1)
            continue

    if not accounts and BANK_FALLBACK_ON and _remaining() > 15:
        print("\n[*] 新注册全失败 → 尝试储备账号兜底（历史成功注册的 wula 订阅，非新注册）", flush=True)
        hit = _use_bank()
        if hit:
            entry, pre_uris, pre_ytext = hit
            age_h = round((time.time() - float(entry.get("ts") or 0)) / 3600, 1)
            print(f"  ⚠️ 兜底: {entry.get('email')} ({age_h}h 前注册) → {len(pre_uris)} 节点", flush=True)
            accounts.append({**{k: v for k, v in entry.items() if k != "ts"},
                             "node_count": len(pre_uris), "bank_fallback": True,
                             "_pre_uris": pre_uris, "_pre_ytext": pre_ytext})
            bank_used = True
    if not accounts:
        print("\n[!!] 所有尝试均失败。", flush=True)
        stopped = True

    # 确定结果保存目录 (CI/GitHub 用 --outdir output)
    if args.outdir:
        save_dir = os.path.expanduser(args.outdir)
        if not os.path.isdir(save_dir):
            try:
                os.makedirs(save_dir, exist_ok=True)
            except Exception as _e:
                print(f"[!] 无法创建目录 {save_dir}: {_e}, 回退到脚本目录")
                save_dir = os.path.dirname(os.path.abspath(__file__)) or "."
    else:
        save_dir = None
        for cand in ("/sdcard/Download", "/storage/emulated/0/Download",
                     "/sdcard/下载", "/storage/emulated/0/下载"):
            if os.path.isdir(cand):
                save_dir = cand
                break
        if save_dir is None:
            save_dir = os.path.dirname(os.path.abspath(__file__)) or "."

    # ===== 订阅 -> 节点 提取 =====
    nodes_all = []
    clash_parts = []
    if accounts:
        print(f"\n[*] 开始提取节点 (clash UA 拉取订阅) ...")
        for idx, a in enumerate(accounts, 1):
            token = a.get("token") or ""
            if not token:
                continue
            if a.get("_pre_uris") is not None:
                ytext = a.get("_pre_ytext") or ""
                uris = a["_pre_uris"]
                err = None
            else:
                ytext, uris, err = _fetch_nodes(token)
            if err:
                print(f"  [{idx}] 订阅拉取失败: {err}")
                continue
            a["node_count"] = len(uris)
            nodes_all.extend(uris)
            clash_parts.append(ytext)
            print(f"  [{idx}] {a['email']}: {len(uris)} 个节点")

    txt_path, json_path, node_path, uniq_n = _save_results(accounts, save_dir, nodes_all)
    if clash_parts:
        with open(os.path.join(save_dir, "clash_all.yaml"), "w", encoding="utf-8") as f:
            f.write("\n".join(clash_parts))

    # 明文打印全部结果
    print("\n" + "=" * 50)
    print(f"[+] 成功 {len(accounts)} 个账号, 去重后 {uniq_n} 个节点, 用时 {round(time.time()-t0,1)}s")
    if bank_used:
        print("[!] 本次为储备账号兜底输出（历史注册账号的订阅），非新注册")
    print("=" * 50)
    for idx, a in enumerate(accounts, 1):
        print(f"\n[{idx}] 邮箱: {a['email']}")
        print("    订阅: 已保存到结果文件（日志隐藏 token）")
        print(f"    节点: {a.get('node_count', 0)} 个 (已在 {node_path} 去重合并)")
    if stopped:
        print("\n[!] 未获得有效节点，请按上述阶段错误诊断。")
    if not uniq_n:
        raise SystemExit(2)


if __name__ == "__main__":
    try:
        main()
    finally:
        # 关键：退出前必须关掉自己起的 mihomo，
        # 否则残留监听会污染后面插件的网络路径
        try:
            _stop_node_proxy()
        except Exception:
            pass
