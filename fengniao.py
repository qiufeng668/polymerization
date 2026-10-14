# @interval: 1d
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from urllib.parse import quote
from urllib.request import Request, urlopen

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

API = "https://api.go01.top/proxy"
AES_IV = b"A-16-Byte-String"

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
    with urlopen(req, timeout=10) as r:
        return {
            "status": r.status,
            "body": r.read().decode("utf-8", "replace"),
            "requestTimestamp": p["requestTimestamp"],
            "requestId": p["requestId"]
        }

def to_trojan_link(plain: str, name: str = "") -> str:
    if not plain:
        return ""
    parts = plain.split(',')
    if len(parts) < 5:
        return ""
    proto, server, port, password, method = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip(), parts[4].strip()
    if proto.lower() != "trojan":
        return ""
    link = f"trojan://{password}@{server}:{port}?encryption={method}"
    if name:
        link += f"#{quote(name)}"
    return link

def fetch_all_nodes(serial: str, delay: float = 2.0) -> str:
    request("/server/info", {}, serial=serial)

    r = request("/user/auto/login", {}, serial=serial)
    body = json.loads(r["body"])
    if body.get("code") != 0:
        print(f"登录失败: {r['body']}")
        return ""
    if "data" not in body or "token" not in body.get("data", {}):
        print("风控提示: 服务端返回 code:0 但未发放 token。")
        return ""
    token = body["data"]["token"]
    print(f"Token 获取成功: {token[:10]}...")

    r = request("/user/fetch/node/list", {"vipType": "vip"}, token=token, serial=serial)
    nodes = json.loads(r["body"]).get("data", [])
    print(f"共发现 {len(nodes)} 个节点")

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
                    time.sleep(delay * 1.5)
        if content:
            pt, key = decrypt_node(content, r["requestTimestamp"], r["requestId"], token)
        node["_plain"] = pt
        if pt:
            link = to_trojan_link(pt, node.get("name", ""))
            if link:
                node_links.append(link)
        if i < len(nodes) - 1:
            time.sleep(delay)

    # 保存为当前目录文件（沙盒会自动收集）
    with open("output_nodes.json", "w", encoding="utf-8") as f:
        json.dump(nodes, f, ensure_ascii=False, indent=2)

    with open("output_nodes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(node_links))

    print(f"已生成节点文件: output_nodes.txt（共 {len(node_links)} 条）")
    return token

def main():
    serial = gen_serial()
    print(f"生成新设备序列号: {serial}")
    fetch_all_nodes(serial, delay=1.0)

if __name__ == "__main__":
    main()
