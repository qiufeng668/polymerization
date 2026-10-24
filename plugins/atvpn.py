#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @interval: 12h
"""ATVPN single-subscription aggregation plugin.

Run: python3 atvpn.py --outdir output
Deps: requests, pyyaml
Outputs: output/subscription.txt (one URL) and output/nodes.txt (plain nodes).
Each run creates one account/subscription. Failed runs never overwrite outputs.
"""
import argparse
import base64
import json
import os
import random
import re
import string
import sys
import time
import urllib.parse as up

try:
    import requests
except ImportError:
    print('[!] missing dependency: requests', flush=True)
    raise SystemExit(2)
try:
    import yaml
except ImportError:
    yaml = None

BASE = 'https://atvpn.cc'
PROMO_CODE = 'nTaSQAXK'
PLAN_ID = 1
PERIOD = 'month_price'
SUB_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
SCHEMES = ('hysteria2', 'hysteria', 'hy2', 'h2', 'vless', 'vmess', 'trojan',
           'ss', 'ssr', 'tuic', 'anytls', 'socks', 'http')


def _safe_error(error):
    text = str(error)
    text = re.sub(r'(?i)(password|token|authorization|auth_data)[=: ]+[^,\s]+', r'\1=[hidden]', text)
    text = re.sub(r'https?://[^\s]+', '[url-hidden]', text)
    return text[:180]


def rand_email():
    name = ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(10))
    return name + '@' + random.choice(('gmail.com', 'outlook.com', 'qq.com', '163.com', 'foxmail.com'))


def rand_password():
    return 'Aa1' + ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(14))


def fmt_auth(auth):
    auth = (auth or '').strip()
    return auth if auth.lower().startswith('bearer ') else 'Bearer ' + auth


def is_node_link(line):
    return '://' in line and line.split('://', 1)[0].lower() in SCHEMES


def _quote(value):
    return up.quote(str(value), safe='')


def _is_ad_name(value):
    name = str(value or '')
    return bool(re.search(r'[@＠][A-Za-z0-9_]+|最新节点|TG频道|Telegram|官方群|官网地址', name, re.I))


def _is_ad_uri(uri):
    if uri.startswith('vmess://'):
        try:
            encoded = uri[8:].split('#', 1)[0]
            value = json.loads(base64.b64decode(encoded + '=' * (-len(encoded) % 4)).decode())
            return _is_ad_name(value.get('ps'))
        except (ValueError, UnicodeError):
            return False
    return _is_ad_name(up.unquote(up.urlsplit(uri).fragment))


def _clean_name(value):
    return str(value or '').strip() or 'ATVPN'


def _node_uri(proxy):
    if not isinstance(proxy, dict):
        raise ValueError('proxy is not object')
    kind = str(proxy.get('type', '')).lower()
    name = _clean_name(proxy.get('name', 'ATVPN'))
    if not name.lower().startswith('atvpn'):
        name = 'atvpn ' + name
    host = str(proxy.get('server', '')).strip()
    port = int(proxy.get('port', 0))
    secret = str(proxy.get('uuid') or proxy.get('password') or '')
    if not host or not secret or not 0 < port < 65536:
        raise ValueError('missing endpoint')
    if host in ('localhost', '::1', '0.0.0.0') or host.startswith('127.'):
        raise ValueError('loopback endpoint')
    server = '[' + host.strip('[]') + ']' if ':' in host else host
    address = '%s:%d' % (server, port)
    fragment = '#' + _quote(name)
    sni = proxy.get('sni') or proxy.get('servername') or ''
    insecure = '1' if proxy.get('skip-cert-verify') else '0'

    if kind in ('hysteria2', 'hy2', 'hysteria'):
        params = {'sni': sni, 'insecure': insecure}
        if proxy.get('obfs'):
            params['obfs'] = proxy['obfs'].get('type', 'salamander') if isinstance(proxy['obfs'], dict) else proxy['obfs']
            params['obfs-password'] = proxy.get('obfs-password', '')
        for key in ('up', 'down', 'alpn'):
            if proxy.get(key) is not None:
                value = proxy[key]
                params[key] = ','.join(value) if isinstance(value, list) else value
        return 'hy2://%s@%s?%s%s' % (_quote(secret), address, up.urlencode(params), fragment)

    if kind == 'anytls':
        params = {'sni': sni, 'insecure': insecure, 'type': 'tcp',
                  'fp': proxy.get('client-fingerprint', 'chrome')}
        return 'anytls://%s@%s?%s%s' % (_quote(secret), address, up.urlencode(params), fragment)

    if kind == 'vless':
        params = {'encryption': 'none', 'type': proxy.get('network', 'tcp')}
        if sni: params['sni'] = sni
        if proxy.get('flow'): params['flow'] = proxy['flow']
        if proxy.get('client-fingerprint'): params['fp'] = proxy['client-fingerprint']
        reality = proxy.get('reality-opts') or {}
        if reality:
            params['security'] = 'reality'
            params['pbk'] = reality.get('public-key', '')
            params['sid'] = reality.get('short-id', '')
        elif proxy.get('tls'):
            params['security'] = 'tls'
            params['allowInsecure'] = insecure
        ws = proxy.get('ws-opts') or {}
        if ws.get('path'): params['path'] = ws['path']
        if (ws.get('headers') or {}).get('Host'): params['host'] = ws['headers']['Host']
        return 'vless://%s@%s?%s%s' % (_quote(secret), address, up.urlencode(params), fragment)

    if kind == 'trojan':
        params = {'sni': sni, 'allowInsecure': insecure, 'type': proxy.get('network', 'tcp')}
        return 'trojan://%s@%s?%s%s' % (_quote(secret), address, up.urlencode(params), fragment)

    if kind == 'ss':
        cipher = str(proxy.get('cipher', ''))
        if not cipher: raise ValueError('SS cipher missing')
        auth = base64.urlsafe_b64encode((cipher + ':' + secret).encode()).decode().rstrip('=')
        return 'ss://%s@%s%s' % (auth, address, fragment)

    if kind == 'vmess':
        data = {'v': '2', 'ps': name, 'add': host.strip('[]'), 'port': str(port),
                'id': secret, 'aid': str(proxy.get('alterId', 0) or 0),
                'net': proxy.get('network', 'tcp'), 'type': 'none',
                'tls': 'tls' if proxy.get('tls') else '', 'sni': sni,
                'path': (proxy.get('ws-opts') or {}).get('path', '/'),
                'host': (proxy.get('ws-opts') or {}).get('headers', {}).get('Host', '')}
        return 'vmess://' + base64.b64encode(json.dumps(data, separators=(',', ':')).encode()).decode()

    if kind == 'tuic':
        params = {'sni': sni, 'congestion_control': proxy.get('congestion-controller', 'cubic'),
                  'udp_relay_mode': proxy.get('udp-relay-mode', 'native')}
        return 'tuic://%s:%s@%s?%s%s' % (_quote(proxy.get('uuid', secret)), _quote(proxy.get('password', secret)), address, up.urlencode(params), fragment)
    raise ValueError('unsupported protocol: ' + kind)


def decode_subscription(body):
    """Decode plain URI list, base64 URI list, or Clash YAML."""
    body = (body or '').lstrip('\ufeff').strip()
    if not body:
        return []
    lines = [line.strip() for line in body.splitlines() if is_node_link(line.strip()) and not _is_ad_uri(line.strip())]
    if lines:
        return lines
    compact = re.sub(r'\s+', '', body) + '=' * (-len(re.sub(r'\s+', '', body)) % 4)
    try:
        decoded = base64.b64decode(compact, validate=True).decode('utf-8')
        lines = [line.strip() for line in decoded.splitlines()
                 if is_node_link(line.strip()) and not _is_ad_uri(line.strip())]
        if lines:
            return lines
    except (ValueError, UnicodeError):
        pass
    if yaml is not None:
        try:
            config = yaml.safe_load(body)
            proxies = config.get('proxies', []) if isinstance(config, dict) else []
            result = []
            for proxy in proxies:
                if isinstance(proxy, dict) and _is_ad_name(proxy.get('name')):
                    continue
                try: result.append(_node_uri(proxy))
                except (ValueError, TypeError, KeyError): pass
            return result
        except yaml.YAMLError:
            pass
    return []


def fetch_subscription(url, session=None):
    last_error = 'empty subscription'
    own = session is None
    session = session or requests.Session()
    try:
        for ua in (SUB_UA, 'Mihomo/1.18.0', 'clash.meta'):
            try:
                response = session.get(url, headers={'User-Agent': ua, 'Accept': '*/*'}, timeout=25)
            except requests.RequestException as error:
                last_error = 'network: ' + type(error).__name__
                continue
            if response.status_code != 200:
                last_error = 'HTTP %d' % response.status_code
                continue
            nodes = decode_subscription(response.text)
            if nodes:
                return nodes, None
            last_error = 'no node links (%d bytes)' % len(response.content)
        return [], last_error
    finally:
        if own: session.close()


class Atvpn:
    def __init__(self, proxy=None):
        self.s = requests.Session()
        self.s.trust_env = not bool(proxy)
        if proxy:
            self.s.proxies.update({'http': proxy, 'https': proxy})
        self.s.headers.update({'User-Agent': SUB_UA, 'Content-Type': 'application/x-www-form-urlencoded',
                               'Accept': 'application/json, text/plain, */*'})
        self.auth = None

    def _post(self, path, data, auth=None):
        headers = {'Authorization': auth} if auth else {}
        response = self.s.post(BASE + path, data=data, timeout=30, headers=headers)
        try: return response.json()
        except ValueError: return {'status': 'fail', 'message': 'HTTP %s' % response.status_code}

    def _get(self, path, auth=None):
        headers = {'Authorization': auth} if auth else {}
        response = self.s.get(BASE + path, timeout=30, headers=headers)
        try: return response.json()
        except ValueError: return {'status': 'fail', 'message': 'HTTP %s' % response.status_code}

    def register(self, email, password):
        return self._post('/api/v1/passport/auth/register', {'email': email, 'password': password, 'invite_code': '', 'email_code': ''})

    def check_coupon(self, code): return self._post('/api/v1/user/coupon/check', {'code': code, 'plan_id': PLAN_ID}, self.auth)
    def create_order(self, code): return self._post('/api/v1/user/order/save', {'plan_id': PLAN_ID, 'period': PERIOD, 'coupon_code': code}, self.auth)
    def checkout(self, trade_no): return self._post('/api/v1/user/order/checkout', {'trade_no': trade_no}, self.auth)
    def get_subscribe(self): return self._get('/api/v1/user/getSubscribe', self.auth)


def do_one(code, proxy=None):
    client = Atvpn(proxy)
    email, password = rand_email(), rand_password()
    print('[*] 注册 ATVPN 账号...', flush=True)
    result = client.register(email, password)
    if result.get('status') != 'success':
        print('[!] 注册失败: %s' % result.get('message'), flush=True); return None
    data = result.get('data') or {}
    token = data.get('token') or ''
    client.auth = fmt_auth(data.get('auth_data') or token)
    if client.check_coupon(code).get('status') != 'success': print('[!] 优惠码失败', flush=True); return None
    order = client.create_order(code)
    if order.get('status') != 'success': print('[!] 下单失败', flush=True); return None
    trade = order.get('data')
    checkout = client.checkout(trade)
    if checkout.get('status') != 'success' and not checkout.get('data'):
        print('[!] 付款失败', flush=True); return None
    sub = client.get_subscribe()
    data = sub.get('data') or {}
    sub_url = data.get('subscribe_url') or (BASE + '/s/' + token if token else '')
    if not sub_url: print('[!] 无订阅链接', flush=True); return None
    nodes, error = fetch_subscription(sub_url, client.s)
    if not nodes: print('[!] 订阅节点为空: ' + str(error), flush=True); return None
    print('[+] 订阅验证通过: %d 条节点' % len(nodes), flush=True)
    return {'subscribe_url': sub_url, 'nodes': nodes}


def _write_outputs(outdir, sub_url, nodes):
    outdir = os.path.abspath(outdir); os.makedirs(outdir, exist_ok=True)
    unique = list(dict.fromkeys(nodes))
    paths = (os.path.join(outdir, 'subscription.txt'), os.path.join(outdir, 'nodes.txt'))
    for path, content in zip(paths, (sub_url.strip() + '\n', '\n'.join(unique) + '\n')):
        temp = path + '.tmp'
        with open(temp, 'w', encoding='utf-8') as f: f.write(content)
        os.replace(temp, path)
    return paths


def main(argv=None):
    parser = argparse.ArgumentParser(description='ATVPN 单账号单订阅插件')
    parser.add_argument('--outdir', default='output')
    parser.add_argument('--code', default=PROMO_CODE)
    parser.add_argument('--proxy', default=os.environ.get('ATVPN_PROXY'))
    args = parser.parse_args(argv)
    result = do_one(args.code, args.proxy)
    if not result:
        print('[!] 本次失败，保留旧输出', flush=True)
        return 2
    sub_path, node_path = _write_outputs(args.outdir, result['subscribe_url'], result['nodes'])
    print('[+] 单订阅已更新：1 条链接，%d 条明文节点' % len(result['nodes']), flush=True)
    print('[+] 输出:', sub_path, node_path, flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
