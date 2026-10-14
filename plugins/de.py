# @interval: 2d
#!/usr/bin/env python3
import re
"""DeVPN 一键拉节点（单文件，拷走即可跑）

    python3 devpn.py

流程：自动注册新账号 → 绑邀请码 → 领免费时长
     → 各地区并发各拉 10 轮并激活 → 保存 nodes.txt / last_account.json

依赖：
  - Python 3
  - 能访问外网
"""
import base64
import hashlib
import json
import os
import random
import ssl
import sys
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ================================================================
# 内嵌：SM3 + SM2 加密
# ================================================================
_SM3_IV = bytes.fromhex("7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e")

def _rotl(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def sm3(msg: bytes) -> bytes:
    ml = len(msg) * 8
    msg = msg + b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += ml.to_bytes(8, "big")
    v = [int.from_bytes(_SM3_IV[j:j + 4], "big") for j in range(0, 32, 4)]
    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
        w = list(int.from_bytes(block[j:j + 4], "big") for j in range(0, 64, 4))
        for j in range(16, 68):
            x = w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15)
            w.append((x ^ _rotl(x, 15) ^ _rotl(x, 23)) ^ _rotl(w[j - 13], 7) ^ w[j - 6])
        wp = [w[j] ^ w[j + 4] for j in range(64)]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            if j < 16:
                t = 0x79CC4519
                ff = a ^ b ^ c
                gg = e ^ f ^ g
            else:
                t = 0x7A879D8A
                ff = (a & b) | (a & c) | (b & c)
                gg = (e & f) | ((~e & 0xFFFFFFFF) & g)
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            tt1 = (ff + d + ss2 + wp[j]) & 0xFFFFFFFF
            tt2 = (gg + h + ss1 + w[j]) & 0xFFFFFFFF
            d = c
            c = _rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = _rotl(f, 19)
            f = e
            e = (tt2 ^ _rotl(tt2, 9) ^ _rotl(tt2, 17)) & 0xFFFFFFFF
        v = [x ^ y for x, y in zip(v, [a, b, c, d, e, f, g, h])]
    return b"".join(x.to_bytes(4, "big") for x in v)

_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
_PUBKEY_HEX = ("04d882d23c6d01534de563f8b10539ac32edf1a4c986ca59044567b86d6c652b2d"
               "34483ba97f9ea3c0950f36697ea858c966af56cc8682c83b83f57c843823aeff")
_PX = int(_PUBKEY_HEX[2:66], 16)
_PY = int(_PUBKEY_HEX[66:130], 16)

def _inv(x):
    return pow(x, _P - 2, _P)

def _point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0: return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _A) * _inv(2 * y1) % _P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)

def _scalar_mul(k, pt):
    k = k % _N
    r = None
    while k:
        if k & 1: r = _point_add(r, pt)
        pt = _point_add(pt, pt)
        k >>= 1
    return r

def _kdf(z: bytes, klen: int) -> bytes:
    ct = 1
    out = b""
    while len(out) < klen:
        out += sm3(z + ct.to_bytes(4, "big"))
        ct += 1
    return out[:klen]

def _sm2_encrypt(msg: bytes) -> bytes:
    g = (_GX, _GY)
    p = (_PX, _PY)
    while True:
        k = random.randrange(1, _N)
        c1 = _scalar_mul(k, g)
        s = _scalar_mul(k, p)
        x2 = s[0].to_bytes(32, "big")
        y2 = s[1].to_bytes(32, "big")
        t = _kdf(x2 + y2, len(msg))
        if any(t): break
    c2 = bytes(a ^ b for a, b in zip(msg, t))
    c3 = sm3(x2 + msg + y2)
    return c1[0].to_bytes(32, "big") + c1[1].to_bytes(32, "big") + c3 + c2

def dsfunique_for(device_id: str) -> str:
    return _sm2_encrypt(device_id.encode("ascii")).
