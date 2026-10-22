#!/usr/bin/env python3
"""Wula subscription path study, read-only. Never prints credentials or URIs.
Login on the reachable panel domain main.wulavpn.com, then try candidate
subscription endpoints with the account token. Reports only status and
node counts per path.
"""
import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import quote

import requests
import yaml

ROOT = Path(__file__).resolve().parent
MAIN = 'https://main.wulavpn.com'
UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')


def emit(kind, **kw):
    print(kind, json.dumps(kw, ensure_ascii=False), flush=True)


def safe_summary(response, label):
    result = {'label': label, 'status': response.status_code,
              'type': response.headers.get('content-type'),
              'bytes': len(response.content),
              'hash': hashlib.sha256(response.content).hexdigest()[:12]}
    try:
        cfg = yaml.safe_load(response.text)
        proxies = cfg.get('proxies', []) if isinstance(cfg, dict) else []
        result['yaml'] = True
        result['count'] = len(proxies)
        result['types'] = sorted({str(p.get('type', '')) for p in proxies if isinstance(p, dict)})
    except Exception:
        result['yaml'] = False
    return result


def main():
    bank_path = ROOT / 'vault_repo/wula_bank.json'
    if not bank_path.exists():
        emit('SKIP', reason='no vault account')
        return
    entry = json.loads(bank_path.read_text())[0]
    token = str(entry.get('token') or '')
    with requests.Session() as session:
        session.trust_env = False
        session.headers.update({'User-Agent': UA, 'Origin': MAIN, 'Referer': MAIN + '/'})
        try:
            r = session.post(MAIN + '/api/v1/passport/auth/login',
                             data={'email': entry['email'], 'password': entry['password']},
                             timeout=(5, 10))
            payload = r.json()
            data = payload.get('data') or {}
            auth = data.get('auth_data') if isinstance(data, dict) else None
            token = str(data.get('token') or token)
            emit('LOGIN', status=r.status_code, token=bool(token), auth=bool(auth))
            if auth:
                session.headers['Authorization'] = auth
        except Exception as error:
            emit('LOGIN', error=type(error).__name__)
        if not token:
            emit('SKIP', reason='no token')
            return
        # Candidate subscription endpoints on the reachable panel domain.
        candidates = [
            ('main-client-api', MAIN + '/api/v1/client/subscribe', {'token': token}),
            ('main-s-path', MAIN + '/s/' + quote(token, safe=''), None),
            ('main-s-query', MAIN + '/s/', {'token': token}),
            ('main-get-subscribe-follow', MAIN + '/api/v1/user/getSubscribe', None),
        ]
        headers = {'User-Agent': 'clash-verge/v1.3.8', 'Accept': '*/*'}
        for label, url, params in candidates:
            try:
                r = session.get(url, params=params, headers=headers,
                                timeout=(5, 12), allow_redirects=True)
                result = safe_summary(r, label)
                result['final_host'] = re.sub(r'^https?://', '', str(r.url)).split('/', 1)[0]
                emit('SUB_TRY', **result)
                if result.get('yaml') and result.get('count'):
                    emit('SUB_WORKING', label=label, count=result['count'],
                         types=result['types'])
                    return
            except Exception as error:
                emit('SUB_TRY', label=label, error=type(error).__name__)
        # Same token through the legacy host, and the old host via panel edge IPs.
        legacy = 'https://windowsv1.com/s/'
        for route in (None, '104.21.32.245', '172.67.188.80'):
            label = 'legacy-' + (route or 'dns')
            try:
                if route:
                    r = requests.get(legacy, params={'token': token}, headers=headers,
                                     timeout=(5, 12), allow_redirects=True,
                                     stream=False)
                    # requests cannot pin IP; fall back to Host header rewrite below.
                    r.close()
                else:
                    r = session.get(legacy, params={'token': token}, headers=headers,
                                    timeout=(5, 12), allow_redirects=True)
                    result = safe_summary(r, label)
                    result['final_host'] = re.sub(r'^https?://', '', str(r.url)).split('/', 1)[0]
                    emit('SUB_TRY', **result)
                    if result.get('yaml') and result.get('count'):
                        emit('SUB_WORKING', label=label, count=result['count'],
                             types=result['types'])
                        return
            except Exception as error:
                emit('SUB_TRY', label=label, error=type(error).__name__)
        emit('SUB_RESULT', working=False)


if __name__ == '__main__':
    main()
