#!/usr/bin/env python3
"""Wula origin study v2, read-only. Never prints credentials, never registers.
Three independent probes:
  ORIGIN2_TLS  - openssl ClientHello with different SNI to 20.46.182.213
  ORIGIN2_PORT - TCP open ports on the origin
  LOGIN/SUB    - existing vault account: login on main.wulavpn.com, refresh subscription
  CN_*         - Chinese-labelled nodes from pools: neutral HTTPS then wula challenge
"""
import collections
import hashlib
import importlib.util
import json
import re
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit

import requests
import yaml

ROOT = Path(__file__).resolve().parent
ORIGIN = '20.46.182.213'
MAIN = 'https://main.wulavpn.com'
START = time.monotonic()
BUDGET = 420
UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')
API = 'http://127.0.0.1:19091'
PROXY = 'http://127.0.0.1:18981'


def emit(kind, **kw):
    print(kind, json.dumps(kw, ensure_ascii=False), flush=True)


def remaining():
    return max(0.0, BUDGET - (time.monotonic() - START))


def tls_probe():
    for sni in ('wula001.com', 'wulass.org', 'main.wulavpn.com', ''):
        cmd = ['timeout', '9', 'openssl', 's_client', '-connect', ORIGIN + ':443', '-tls1_2']
        if sni:
            cmd += ['-servername', sni]
        started = time.monotonic()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=12, input='')
            out = (proc.stdout or '') + (proc.stderr or '')
            match = re.search(r'subject=(.*)', out)
            emit('ORIGIN2_TLS', sni=sni or 'none', exit=proc.returncode,
                 connected='CONNECTED' in out, subject=match.group(1)[:90] if match else None,
                 seconds=round(time.monotonic() - started, 2))
        except Exception as error:
            emit('ORIGIN2_TLS', sni=sni or 'none', error=type(error).__name__)


def port_scan():
    ports = [80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880]

    def test(port):
        try:
            with socket.create_connection((ORIGIN, port), timeout=2.0):
                return port
        except OSError:
            return None
    with ThreadPoolExecutor(max_workers=6) as pool:
        open_ports = [p for p in pool.map(test, ports) if p]
    emit('ORIGIN2_PORT', open=open_ports)


def login_refresh(bank):
    entry = bank[0]
    with requests.Session() as session:
        session.trust_env = False
        session.headers.update({'User-Agent': UA, 'Origin': MAIN, 'Referer': MAIN + '/'})
        try:
            r = session.post(MAIN + '/api/v1/passport/auth/login',
                             data={'email': entry['email'], 'password': entry['password']},
                             timeout=(5, 10))
            emit('LOGIN', status=r.status_code, type=r.headers.get('content-type'), bytes=len(r.content))
            payload = r.json()
            data = payload.get('data') or {}
            auth = data.get('auth_data') if isinstance(data, dict) else None
            emit('LOGIN_FIELDS', keys=list(payload), data_keys=list(data) if isinstance(data, dict) else [],
                 auth=bool(auth))
            if not auth:
                return
            session.headers['Authorization'] = auth
            for path in ('/api/v1/user/info', '/api/v1/user/getSubscribe'):
                try:
                    r = session.get(MAIN + path, timeout=(5, 10))
                    emit('LOGIN_API', path=path, status=r.status_code)
                    if not r.ok:
                        continue
                    payload = r.json()
                    data = payload.get('data') or {}
                    if not isinstance(data, dict):
                        emit('LOGIN_API_DATA', path=path, keys=list(payload))
                        continue
                    emit('LOGIN_API_DATA', path=path, keys=list(data))
                    if not path.endswith('getSubscribe'):
                        continue
                    url = str(data.get('subscribe_url') or '')
                    host = urlsplit(url).hostname if url.startswith('https://') else None
                    emit('SUB_ENTRY', host=host, official=bool(host))
                    if not host:
                        continue
                    try:
                        r = session.get(url, headers={'User-Agent': 'clash-verge/v1.3.8'},
                                        timeout=(5, 12))
                        cfg = yaml.safe_load(r.text)
                        proxies = cfg.get('proxies', []) if isinstance(cfg, dict) else []
                        emit('SUB_DOWNLOAD', host=host, status=r.status_code, bytes=len(r.content),
                             count=len(proxies),
                             types=sorted({p.get('type', '') for p in proxies if isinstance(p, dict)}))
                    except Exception as error:
                        emit('SUB_DOWNLOAD', host=host, error=type(error).__name__)
                except Exception as error:
                    emit('LOGIN_API', path=path, error=type(error).__name__)
        except Exception as error:
            emit('LOGIN', error=type(error).__name__)


CN_PAT = re.compile(r'中国|大陸|大陆|回国|上海|北京|广州|深圳|沪|京|粤|广|电信|联通|移动|\bCN\b|China', re.I)
KEEP_TYPES = ('vless', 'vmess', 'ss', 'trojan', 'hysteria2', 'anytls', 'tuic')


def cn_pool():
    result = []
    vault = ROOT / 'vault_repo'

    def add(items):
        for raw in items:
            if not isinstance(raw, dict):
                continue
            if not CN_PAT.search(str(raw.get('name') or '')):
                continue
            if raw.get('type') not in KEEP_TYPES or not raw.get('server') or not raw.get('port'):
                continue
            result.append(raw)
    try:
        cfg = yaml.safe_load((vault / 'clash.yaml').read_text())
        add(cfg.get('proxies', []) if isinstance(cfg, dict) else [])
    except Exception as error:
        emit('CN_SOURCE', name='clash.yaml', error=type(error).__name__)
    try:
        cfg = json.loads((vault / 'wula_pool.json').read_text())
        add(list((cfg.get('nodes') or {}).values()))
    except Exception as error:
        emit('CN_SOURCE', name='wula_pool.json', error=type(error).__name__)
    try:
        spec = importlib.util.spec_from_file_location('engine', ROOT / 'main_engine.py')
        engine = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(engine)
        state = json.loads((vault / 'cache_state.json').read_text())
        for info in state.values():
            if isinstance(info, dict):
                for uri in info.get('nodes', []):
                    node = engine.uri_to_clash_proxy(uri)
                    if node:
                        add([node])
    except Exception as error:
        emit('CN_SOURCE', name='plugin-cache', error=type(error).__name__)
    unique, seen = [], set()
    for raw in result:
        node = {k: v for k, v in raw.items() if k not in ('name', 'egress', 'exit_ip')}
        fingerprint = hashlib.sha256(json.dumps(node, sort_keys=True, default=str).encode()).hexdigest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        node['name'] = 'cn' + str(len(unique)).zfill(3)
        unique.append(node)
    emit('CN_POOL', count=len(unique), types=dict(collections.Counter(x['type'] for x in unique)))
    return unique


def config(nodes):
    return {'mixed-port': 18981, 'external-controller': '127.0.0.1:19091', 'allow-lan': False,
            'bind-address': '127.0.0.1', 'mode': 'rule', 'log-level': 'silent',
            'proxies': nodes,
            'proxy-groups': [{'name': 'OUT', 'type': 'select', 'proxies': [x['name'] for x in nodes]}],
            'rules': ['MATCH,OUT']}


def validate(nodes, folder):
    if not nodes:
        return []
    path = folder / 'validate.yaml'
    path.write_text(yaml.safe_dump(config(nodes), allow_unicode=True, sort_keys=False))
    proc = subprocess.run(['mihomo', '-t', '-d', str(folder), '-f', str(path)],
                          capture_output=True, timeout=12)
    if proc.returncode == 0:
        return nodes
    if len(nodes) == 1:
        emit('CN_INVALID', node=nodes[0]['name'], type=nodes[0]['type'])
        return []
    mid = len(nodes) // 2
    return validate(nodes[:mid], folder) + validate(nodes[mid:], folder)


def delay(node):
    if remaining() < 60:
        return None
    try:
        r = requests.get(API + '/proxies/' + node['name'] + '/delay',
                         params={'url': 'https://www.gstatic.com/generate_204', 'timeout': 4500},
                         timeout=(2, 6))
        data = r.json()
        if r.status_code == 200 and isinstance(data.get('delay'), (int, float)):
            return (data['delay'], node)
    except Exception:
        pass
    return None


def challenge_summary(r):
    fields, complete = [], False
    try:
        payload = r.json()
        if isinstance(payload, dict):
            fields = list(payload)
            complete = bool(payload.get('token') and payload.get('challenge')
                            and payload.get('instrumentation'))
    except ValueError:
        pass
    return {'status': r.status_code, 'bytes': len(r.content),
            'hash': hashlib.sha256(r.content).hexdigest()[:12], 'complete': complete, 'fields': fields}


def cn_study(bank):
    nodes = cn_pool()
    if not nodes:
        emit('CN_RESULT', nodes=0)
        return
    with tempfile.TemporaryDirectory(prefix='wula-cn-') as tmp:
        folder = Path(tmp)
        nodes = validate(nodes, folder)
        emit('CN_VALID', count=len(nodes))
        if not nodes:
            return
        conf = folder / 'config.yaml'
        conf.write_text(yaml.safe_dump(config(nodes), allow_unicode=True, sort_keys=False))
        process = subprocess.Popen(['mihomo', '-d', str(folder), '-f', str(conf)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(25):
                try:
                    if requests.get(API + '/version', timeout=.4).ok:
                        break
                except Exception:
                    pass
                time.sleep(.15)
            alive, done = [], 0
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(delay, node) for node in nodes]
                for future in as_completed(futures):
                    done += 1
                    value = future.result()
                    if value:
                        alive.append(value)
            alive.sort(key=lambda item: item[0])
            emit('CN_ALIVE', tested=done, count=len(alive))
            token = bank[0].get('token', '') if bank else ''
            for latency, node in alive[:10]:
                if remaining() < 45:
                    break
                emit('CN_TRY', node=node['name'], type=node['type'], latency=latency)
                try:
                    requests.put(API + '/proxies/OUT', json={'name': node['name']}, timeout=3)
                except Exception:
                    continue
                with requests.Session() as session:
                    session.trust_env = False
                    session.proxies.update({'http': PROXY, 'https': PROXY})
                    session.headers.update({'User-Agent': UA, 'Origin': 'https://wula001.com',
                                            'Referer': 'https://wula001.com/'})
                    try:
                        r = session.get('https://www.cloudflare.com/cdn-cgi/trace', timeout=(3, 5))
                        trace = dict(x.split('=', 1) for x in r.text.splitlines() if '=' in x)
                        emit('CN_LOC', node=node['name'], loc=trace.get('loc'),
                             exit_hash=hashlib.sha256(trace.get('ip', '').encode()).hexdigest()[:10])
                    except Exception as error:
                        emit('CN_LOC', node=node['name'], error=type(error).__name__)
                    for host in ('wula001.com', 'wulass.org'):
                        try:
                            r = session.post('https://' + host + '/fd0fb2130e/challenge',
                                             json={}, timeout=(4, 7))
                            emit('CN_TARGET', node=node['name'], host=host, **challenge_summary(r))
                            if challenge_summary(r)['complete']:
                                emit('CN_WORKING', node=node['name'], host=host)
                                return
                        except Exception as error:
                            emit('CN_TARGET', node=node['name'], host=host, error=type(error).__name__)
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
    emit('CN_RESULT', working=False, seconds=round(time.monotonic() - START, 1))


def main():
    tls_probe()
    port_scan()
    bank_path = ROOT / 'vault_repo/wula_bank.json'
    bank = json.loads(bank_path.read_text()) if bank_path.exists() else []
    emit('BANK', count=len(bank))
    if bank:
        login_refresh(bank)
    else:
        emit('LOGIN', skip='no bank entry')
    if remaining() > 60:
        cn_study(bank)
    emit('ORIGIN2_DONE', seconds=round(time.monotonic() - START, 1))


if __name__ == '__main__':
    main()
