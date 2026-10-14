# @interval: 12h
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
小满VPN 全自动注册 + 自动接码 + 导出节点 (沙盒极简版)
只输出最终的 vless 节点，供聚合器使用。
"""
import uuid, json, base64, hashlib, time, re, string, random, gzip
import urllib.request, urllib.error, urllib.parse
import os

# ---------------- 小满接口 ----------------
SEND_CODE_URL = "https://xiaomans.com/vela-api/api/v1/auth/send-code"
REGISTER_URL  = "https://xiaomans.com/vela-api/api/v1/auth/register"
NODES_URL     = "https://xiaomans.com/vela-api/api/v1/nodes"
SELECT_URL    = "https://xiaomans.com/vela-api/api/v1/nodes/select"
SINGBOX_URL   = "https://xiaomans.com/vela-api/api/v1/config/singbox"

# ---------------- emailnator 接口 ----------------
EMAILNATOR     = "https://www.emailnator.com"
GEN_EMAIL_URL  = f"{EMAILNATOR}/api/generate-email"
MSG_LIST_URL   = f"{EMAILNATOR}/api/message-list"
MSG_URL        = f"{EMAILNATOR}/api/message"

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

XIAOMAN_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": "xiaoman Android",
    "Accept-Language": "zh-CN",
    "X-App-Brand": "xiaoman",
    "X-Vela-Client-Platform": "android",
    "X-Vela-App-Version": "1.14.0-alpha.21",
    "X-Vela-Build": "668",
    "Host": "xiaomans.com",
    "Connection": "Keep-Alive",
}

def _http(method, url, body=None, headers=None, timeout=20):
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.headers.get("Content-Encoding", "") == "gzip":
                raw = gzip.decompress(raw)
            return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read()
        if e.headers.get("Content-Encoding", "") == "gzip":
            raw = gzip.decompress(raw)
        return e.code, raw
    except Exception as e:
        return 500, str(e).encode("utf-8")

def http_post_json(url, body, headers=None):
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        h.update(headers)
    st, raw = _http("POST", url, body=body, headers=h)
    try:
        return st, json.loads(raw.decode("utf-8", "replace"))
    except:
        return st, {}

def http_get_json(url, params=None, headers=None):
    if params:
        url += "?" + "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
    h = {"Accept": "application/json"}
    if headers:
        h.update(headers)
    st, raw = _http("GET", url, headers=h)
    try:
        return st, json.loads(raw.decode("utf-8", "replace"))
    except:
        return st, {}

# ---------------- 纯 Python AES-256-GCM (修复版) ----------------
_SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _rot_word(w): return ((w << 8) | (w >> 24)) & 0xffffffff
def _sub_word(w):
    return (_SBOX[(w >> 24) & 0xff] << 24 | _SBOX[(w >> 16) & 0xff] << 16 |
            _SBOX[(w >> 8) & 0xff] << 8 | _SBOX[w & 0xff])

def _expand_key(key):
    Nk, Nr = 8, 14
    w = [int.from_bytes(key[4 * i: 4 * i + 4], "big") for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        t = w[i - 1]
        if i % Nk == 0:
            t = _sub_word(_rot_word(t)) ^ (_RCON[i // Nk - 1] << 24)
        elif Nk > 6 and i % Nk == 4:
            t = _sub_word(t)
        w.append(w[i - Nk] ^ t)
    return w

def _mul2(x): return ((x << 1) ^ (0x1b if x & 0x80 else 0)) & 0xff
def _mul3(x): return _mul2(x) ^ x

def _encrypt_block(key, pt):
    w = _expand_key(key)
    s = list(pt)
    def add_round_key(rnd):
        for c in range(4):
            word = w[rnd * 4 + c]
            for r in range(4):
                s[4 * c + r] ^= (word >> (24 - 8 * r)) & 0xff
    def sub_bytes():
        for i in range(16):
            s[i] = _SBOX[s[i]]
    def shift_rows():
        for r in range(1, 4):
            row = [s[4 * c + r] for c in range(4)]
            row = row[r:] + row[:r]
            for c in range(4):
                s[4 * c + r] = row[c]
    def mix_columns():
        for c in range(4):
            a = [s[4 * c + r] for r in range(4)]
            s[4 * c + 0] = _mul2(a[0]) ^ _mul3(a[1]) ^ a[2] ^ a[3]
            s[4 * c + 1] = a[0] ^ _mul2(a[1]) ^ _mul3(a[2]) ^ a[3]
            s[4 * c + 2] = a[0] ^ a[1] ^ _mul2(a[2]) ^ _mul3(a[3])
            s[4 * c + 3] = _mul3(a[0]) ^ a[1] ^ a[2] ^ _mul2(a[3])
    add_round_key(0)
    for rnd in range(1, 14):
        sub_bytes(); shift_rows(); mix_columns(); add_round_key(rnd)
    sub_bytes(); shift_rows(); add_round_key(14)
    return bytes(s)

def _gf_mul(x, y):
    z = 0; v = y; R = 0xe1000000000000000000000000000000
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ R if v & 1 else v >> 1
    return z

def _ghash(H, C):
    pad = C if len(C) % 16 == 0 else C + b"\x00" * (16 - len(C) % 16)
    data = pad + (len(C) * 8).to_bytes(8, "big")
    y = 0
    for i in range(0, len(data), 16):
        y = _gf_mul(y ^ int.from_bytes(data[i:i + 16], "big"), H)
    return y

def aes_gcm_decrypt(key, nonce, ciphertext, tag):
    H = int.from_bytes(_encrypt_block(key, b"\x00" * 16), "big")
    J0 = nonce + b"\x00\x00\x00\x01"
    EJ0 = _encrypt_block(key, J0)
    counter = (int.from_bytes(J0, "big") + 1) & ((1 << 128) - 1)
    pt = b""
    for i in range(0, len(ciphertext), 16):
        blk = ciphertext[i:i + 16]
        ks = _encrypt_block(key, counter.to_bytes(16, "big"))
        pt += bytes(a ^ b for a, b in zip(blk, ks))
        counter = (counter + 1) & ((1 << 128) - 1)
    calc = (_ghash(H, ciphertext) ^ int.from_bytes(EJ0, "big")).to_bytes(16, "big")
    if calc != tag:
        raise ValueError("GCM 校验失败: token 可能已失效")
    return pt

# ---------------- emailnator 邮箱 ----------------
def generate_alias_email():
    r = http_post_json(GEN_EMAIL_URL, {"ids": [2]},
                       headers={"User-Agent": BROWSER_UA})
    email = (r[1] or {}).get("email")
    if not email:
        raise RuntimeError(f"生成邮箱失败: {r[1]}")
    return email

def fetch_verification_code(email, timeout=120, interval=5):
    print(f"      开始轮询收件箱 (每{interval}秒一次, 最长{timeout}秒)...")
    start = time.time()
    deadline = start + timeout
    while time.time() < deadline:
        try:
            r = http_post_json(MSG_LIST_URL, {"email": email, "limit": 20},
                               headers={"User-Agent": BROWSER_UA})
            msgs = (r[1] or {}).get("messages") or []
        except Exception as ex:
            print(f"      [!] 收件箱查询异常: {ex}")
            time.sleep(interval)
            continue
        for m in msgs:
            frm = m.get("from") or ""
            subj = m.get("subject") or ""
            if "xiaomans" in frm.lower() or "小满" in subj:
                m_subj = re.search(r"\b(\d{4,8})\b", subj)
                if m_subj:
                    return m_subj.group(1)
                r2 = http_get_json(f"{MSG_URL}/{m['id']}",
                                   headers={"User-Agent": BROWSER_UA})
                text = re.sub(r"<[^>]+>", " ", (r2[1] or {}).get("content", ""))
                six = [x for x in re.findall(r"\b(\d{4,8})\b", text) if len(x) == 6]
                if six:
                    return six[0]
        waited = int(time.time() - start)
        print(f"      ... 等待验证码中 {waited}s / {timeout}s")
        time.sleep(interval)
    raise TimeoutError(f"等待验证码超时({timeout}s): {email}")

# ---------------- 小满 API ----------------
def _xiaoman_headers(token=None):
    h = dict(XIAOMAN_HEADERS)
    if token:
        h["Authorization"] = f"Bearer {token}"
        h["X-Vela-Encrypted"] = "1"
    return h

def decrypt_payload(raw, token):
    key = hashlib.sha256(f"vela-api-payload-v1:{token}".encode()).digest()
    nonce = base64.b64decode(raw["nonce"])
    cipher = base64.b64decode(raw["payload"])
    tag = base64.b64decode(raw.get("tag", ""))
    if not tag:
        tag = cipher[-16:]
        cipher = cipher[:-16]
    return json.loads(aes_gcm_decrypt(key, nonce, cipher, tag))

def get_nodes_data(token):
    st, raw = http_get_json(NODES_URL, params={"refresh": 1},
                            headers=_xiaoman_headers(token))
    return decrypt_payload(raw, token)

def get_nodes(token):
    data = get_nodes_data(token)
    free = [it["id"] for it in data.get("free_items", [])]
    paid = [it["id"] for it in data.get("paid_items", [])]
    return free + paid

def select_node(token, node_id):
    http_post_json(SELECT_URL, {"node_id": node_id}, headers=_xiaoman_headers(token))

def get_singbox_config(token):
    st, raw = http_get_json(SINGBOX_URL,
                            params={"platform": "android", "routing_mode": "smart"},
                            headers=_xiaoman_headers(token))
    return decrypt_payload(raw, token)

def singbox_to_vless_link(sbox_cfg, node_name):
    vless = None
    for out in sbox_cfg.get("outbounds", []):
        if out.get("type") == "vless":
            vless = out
            break
    if not vless:
        return None
    tls = vless.get("tls") or {}
    reality = tls.get("reality") or {}
    return ("vless://{uuid}@{host}:{port}?type=tcp&security=reality"
            "&pbk={pbk}&fp={fp}&sni={sni}&sid={sid}&flow={flow}#{name}").format(
        uuid=vless["uuid"], host=vless["server"], port=vless["server_port"],
        pbk=reality.get("public_key", ""), fp=(tls.get("utls") or {}).get("fingerprint", ""),
        sni=tls.get("server_name", ""), sid=reality.get("short_id", ""),
        flow=vless.get("flow", ""), name=urllib.parse.quote(node_name))

def export_nodes(token):
    node_data = get_nodes_data(token)
    node_ids = []
    for it in node_data.get("free_items", []):
        node_ids.append(it["id"])
    for it in node_data.get("paid_items", []):
        node_ids.append(it["id"])

    links = []
    for nid in node_ids:
        try:
            select_node(token, nid)
            time.sleep(0.4)
            cfg = get_singbox_config(token)
            # 从原始列表中找个友好的名字，找不到就用 ID
            name = nid
            for it in node_data.get("items", []):
                if it.get("id") == nid:
                    name = it.get("name", nid)
                    break
            link = singbox_to_vless_link(cfg, name)
            if link:
                links.append(link)
        except Exception:
            pass
        time.sleep(0.4)
    return links

# ---------------- 随机密码 ----------------
def random_password(length=16):
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*"
    pool = upper + lower + digits + symbols
    pwd = [random.choice(upper), random.choice(lower),
           random.choice(digits), random.choice(symbols)]
    pwd += [random.choice(pool) for _ in range(length - 4)]
    random.shuffle(pwd)
    return "".join(pwd)

# ---------------- 主流程 ----------------
def main():
    print("=" * 52)
    print("  小满VPN 全自动注册 (沙盒集成版 · 仅输出节点)")
    print("=" * 52)

    password = random_password()
    print(f"[0/5] 随机密码: {password}")

    code = None
    email = None
    device_id = None
    for attempt in range(1, 4):
        email = generate_alias_email()
        device_id = str(uuid.uuid4())
        print(f"[1/5] 自动申请邮箱({attempt}): {email}")

        st, r = http_post_json(SEND_CODE_URL,
                               {"email": email, "type": 2, "device_id": device_id},
                               headers=_xiaoman_headers())
        print(f"[2/5] 发送验证码: HTTP {st}")
        if st != 200:
            print(f"      send-code 失败, 换邮箱重试...")
            continue

        try:
            code = fetch_verification_code(email)
            break
        except TimeoutError as ex:
            print(f"      {ex}  换邮箱重试...")
            continue

    if not code:
        print("多次尝试仍未能收到验证码, 稍后重试")
        return

    print(f"[3/5] 提取验证码: {code}")

    body = {
        "email": email, "password": password, "name": "", "code": code,
        "invite_code": "", "device_id": device_id,
        "device_name": "Xiaomi 2211133C", "device_platform": "Android",
        "device_location": "当前网络",
    }
    st, r = http_post_json(REGISTER_URL, body, headers=_xiaoman_headers())
    print(f"[4/5] 注册: HTTP {st}")
    token = r.get("token") or (r.get("data") or {}).get("token")
    if not token:
        print(f"注册返回无 token, 可能遇到风控。")
        return
    print(f"       token获取成功!")

    print(f"[5/5] 拉取并解密节点...")
    links = export_nodes(token)
    
    # 仅保留纯粹的节点输出供沙盒捕获
    out_file = "xiaoman_nodes.txt"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(links) + "\n")
        
    print("=" * 52)
    print(f"[+] 注册及拉取成功: {email}")
    print(f"[+] 节点 {len(links)} 条, 已生成 {out_file}")

if __name__ == "__main__":
    main()
