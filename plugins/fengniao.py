#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
蜂鸟加速器 - 自动注册并拉取节点解密（精简版，保存至 Download）
用法:
    python fengniao_sign.py                      # 随机新号注册
    python fengniao_sign.py --serial X           # 使用指定序列号
    python fengniao_sign.py --delay 2.0          # 节点请求间隔（秒）
"""
import base64
import hashlib
import json
import os
import ssl
import sys
import time
import uuid
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

API = "https://api.go01.top/proxy"
AES_IV = b"A-16-Byte-String"
OUTPUT_DIR = "/storage/emulated/0/Download/"   # 输出目录

# 服务端 TLS 栈对 urllib 默认握手不兼容（POST 时 SSLEOFError）。
# 用显式 TLS1.2+ 的 SSLContext 保证握手成功。
_TLS_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_TLS_CTX.check_hostname = False
_TLS_CTX.verify_mode = ssl.CERT_NONE
_TLS_CTX.minimum_version = ssl.TLSVersion.TLSv1_2

def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

def build_decrypt_key(ts_str: str, rid: str, token: str) -> str:
    if int(ts_str) % 2 == 0:
        seq = [("rid", 16), ("rid", 8), ("ts", -3), ("rid", 12), ("rid", 26), ("ts", -2), ("rid", 2), ("rid", 18),
               ("tok", 16), ("tok", 8), ("ts", -3), ("tok", 12), ("tok", 26), ("ts", -2), ("tok", 2), ("tok", 18)]
    else:
        seq = [("rid", 5), ("rid", 11), ("ts", -2), ("rid", 8), ("rid", 27), ("ts", -1), ("rid", 9), ("rid", 21),
               ("tok", 5), ("tok", 11), ("ts", -2), ("tok", 8), ("tok", 27), ("ts", -1), ("tok", 9), ("tok", 21)]
    out = []
    for src, idx in seq:
        s = rid if src == "rid" else (ts_str if src == "ts" else token)
        out.append(s[idx])
    return "".join(out)

def decrypt_node(content_b64: str, ts_str: str, rid: str, token: str):
    key = build_decrypt_key(ts_str, rid, token)
    aes = AES.new(key.encode(), AES.MODE_CBC, AES_IV)
    try:
        pt = unpad(aes.decrypt(base64.b64decode(content_b64)), 16)
        return pt.decode("utf-8", errors="replace"), key
    except Exception:
        return None, key

def build_key(ts_str: str, rid: str, token: str) -> str:
    L = len(ts_str)
    ts2 = ts_str[L - 2]
    if int(ts_str) % 2 == 0:
        k8 = rid[16] + rid[8] + ts_str[L - 3] + rid[12] + rid[26] + ts2 + rid[2] + rid[18]
    else:
        k8 = rid[5] + rid[11] + ts2 + rid[8] + rid[27] + ts_str[L - 1] + rid[9] + rid[21]
    idx = int(ts2)
    k8 += (token[idx] if token else rid[idx])
    return k8

def gen_serial() -> str:
    return base64.b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes[:16]).decode()

def make_sign(params: dict, token: str, serial: str) -> tuple:
    now = int(time.time() * 1000)
    rid = uuid.uuid4().hex
    p = dict(params)
    p.update({
        "version": "v3.1.1",
        "rankVersion": "10",
        "serialNumber": serial,
        "requestTimestamp": str(now),
        "requestId": rid,
        "clientType": "Android",
        "promoteChannel": "S100",
        "clientModel": "XT2201-2",
    })
    if token:
        p["token"] = token
    ps = "&".join(f"{k}={p[k]}" for k in sorted(p))
    key = build_key(str(now), rid, token)
    sign = md5(ps + key)
    return p, sign

def request(path: str, params: dict, token: str = "", serial: str = "") -> dict:
    p, sign = make_sign(params, token, serial)
    boundary = uuid.uuid4().hex
    parts = []
    for k, v in {**p, "sign": sign}.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n')
    data = ("".join(parts) + f"--{boundary}--\r\n").encode()
    req = Request(f"{API}{path}", data=data, method="POST")
    req.add_header("User-Agent", "okhttp-okgo/jeasonlzy")
    req.add_header("Accept-Language", "zh-CN,zh;q=0.8")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    with urlopen(req, timeout=10, context=_TLS_CTX) as r:
        return {
            "status": r.status,
            "body": r.read().decode("utf-8", "replace"),
            "requestTimestamp": p["requestTimestamp"],
            "requestId": p["requestId"]
        }

def to_trojan_link(plain: str, name: str = "") -> str:
    """
    将明文节点转换为 Trojan 链接
    明文格式: 协议,服务器,端口,密码,加密
    若协议不是 trojan，返回空字符串
    """
    if not plain:
        return ""
    parts = plain.split(',')
    if len(parts) < 5:
        return ""
    proto, server, port, password, method = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip(), parts[4].strip()
    if proto.lower() != "trojan":
        return ""  # 只处理 trojan
    # 构造链接
    link = f"trojan://{password}@{server}:{port}?encryption={method}"
    if name:
        link += f"#{quote(name)}"
    return link

def fetch_all_nodes(serial: str, delay: float = 2.0) -> str:
    print("== server/info ==")
    request("/server/info", {}, serial=serial)

    print("== user/auto/login ==")
    r = request("/user/auto/login", {}, serial=serial)
    body = json.loads(r["body"])
    if body.get("code") != 0:
        print("登录失败:", r["body"])
        return ""
    if "data" not in body or "token" not in body.get("data", {}):
        print("风控提示: 服务端返回 code:0 但未发放 token（新号注册频繁被临时风控）。")
        print("  稍等几分钟重试，或改用 --serial <已有账号序列号> 跳过注册。")
        return ""
    token = body["data"]["token"]
    print(f"token: {token}  (registerGift: {body['data'].get('registerGift')})")

    print("== user/my/info ==")
    r = request("/user/my/info", {}, token=token, serial=serial)
    try:
        info = json.loads(r["body"])["data"]
        print(f"  账号 {info.get('account')}  vipEndTime={info.get('vipEndTime')}  recommenderId={info.get('recommenderId')}")
    except Exception:
        pass

    print("== user/fetch/node/list ==")
    r = request("/user/fetch/node/list", {"vipType": "vip"}, token=token, serial=serial)
    nodes = json.loads(r["body"])["data"]
    print(f"共 {len(nodes)} 个节点（详情间隔 {delay}s）")

    # 存储所有节点明文和链接
    node_links = []
    for i, node in enumerate(nodes):
        content, pt, key = "", None, ""
        for attempt in range(3):
            r = request("/user/fetch/node/detail", {"nodeId": node["id"]}, token=token, serial=serial)
            try:
                content = json.loads(r["body"])["data"]["content"]
                break
            except Exception:
                if attempt < 2:
                    print(f"  {node['name']}: 重试 {attempt+1}/2 ...")
                    time.sleep(delay * 2)
                else:
                    print(f"  {node['name']}: 失败 {r['body'][:120]}")
        if content:
            pt, key = decrypt_node(content, r["requestTimestamp"], r["requestId"], token)
            print(f"  {node['name']:8s} key={key}  ->  {pt if pt else 'FAIL'}")
        node["_plain"] = pt
        # 生成 Trojan 链接
        if pt:
            link = to_trojan_link(pt, node.get("name", ""))
            if link:
                node_links.append(link)
        if i < len(nodes) - 1:
            time.sleep(delay)

    # 保存 JSON 到 Download 目录（目录不存在则回退到当前目录）
    out_dir = OUTPUT_DIR
    if not os.path.isdir(out_dir):
        out_dir = "./"
    json_path = f"{out_dir}fengniao_nodes_{serial[:8]}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(nodes, f, ensure_ascii=False, indent=2)
    print(f"JSON 已保存至 {json_path}")

    # 保存 Trojan 链接到 Download 目录
    links_path = f"{out_dir}节点链接.txt"
    with open(links_path, "w", encoding="utf-8") as f:
        f.write("\n".join(node_links))
    print(f"Trojan 链接已保存至 {links_path}（共 {len(node_links)} 条）")

    return token

def main():
    args = sys.argv[1:]
    serial = next((a.split("=", 1)[1] for a in args if a.startswith("--serial=")), "")
    delay = float(next((a.split("=", 1)[1] for a in args if a.startswith("--delay=")), "2.0"))

    if not serial:
        serial = gen_serial()
        print(f"生成新序列号: {serial} （新账号）")
    else:
        print(f"使用指定序列号: {serial}")

    token = fetch_all_nodes(serial, delay)
    if token:
        print("注册 + 节点拉取完成。所有文件已保存至 /storage/emulated/0/Download/")

if __name__ == "__main__":
    main()