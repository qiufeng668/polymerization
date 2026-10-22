"""Read-only CI network diagnosis with repeated-attempt success rates.

Distinguishes three hypotheses for the captcha host:
  A) consistent block        -> every attempt fails
  B) intermittent loss       -> some attempts succeed
  C) TLS-layer interference  -> TCP ok but handshake fails consistently

No registration, no redemption, no credentials in logs.
"""
import json
import os
import platform
import socket
import ssl
import time

import requests

ATTEMPTS = 5
ORIGIN = '20.46.182.213'
HOSTS = ['wulass.org', 'wula001.com']
PANEL = 'main.wulavpn.com'


def emit(kind, **kw):
    print(kind, json.dumps(kw, ensure_ascii=False), flush=True)


def egress():
    for url in ('https://api.ipify.org', 'https://ifconfig.me/ip'):
        try:
            with requests.get(url, timeout=(4, 8)) as response:
                return response.text.strip()
        except Exception:
            continue
    return None


def tcp(ip, timeout=4.0):
    started = time.monotonic()
    try:
        with socket.create_connection((ip, 443), timeout=timeout):
            return 'ok', round((time.monotonic() - started) * 1000)
    except Exception as error:
        return type(error).__name__, round((time.monotonic() - started) * 1000)


def tls(ip, sni, timeout=6.0):
    context = ssl.create_default_context()
    started = time.monotonic()
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=sni):
                return 'ok', round((time.monotonic() - started) * 1000)
    except Exception as error:
        return type(error).__name__, round((time.monotonic() - started) * 1000)


def challenge(host, timeout=9.0):
    started = time.monotonic()
    try:
        with requests.Session() as session:
            session.trust_env = False
            response = session.post(
                'https://' + host + '/fd0fb2130e/challenge',
                headers={'User-Agent': 'Mozilla/5.0', 'Origin': 'https://' + host},
                timeout=(5, timeout))
        elapsed = round((time.monotonic() - started) * 1000)
        if response.status_code != 200:
            return 'HTTP_%d' % response.status_code, elapsed
        try:
            payload = response.json()
        except ValueError:
            return 'bad_body', elapsed
        complete = bool(payload.get('token') and payload.get('challenge') and payload.get('instrumentation'))
        return ('complete' if complete else 'incomplete'), elapsed
    except Exception as error:
        return type(error).__name__, round((time.monotonic() - started) * 1000)


def main():
    emit('ENV', runner=platform.system(), machine=platform.machine(),
         tls=ssl.OPENSSL_VERSION, proxy_vars=[k for k in os.environ if 'proxy' in k.lower()])
    emit('EGRESS', ip=egress())

    for host in HOSTS:
        tcp_r, tls_r, http_r = [], [], []
        for _ in range(ATTEMPTS):
            kind, ms = tcp(ORIGIN)
            tcp_r.append('%s/%dms' % (kind, ms))
            kind, ms = tls(ORIGIN, host)
            tls_r.append('%s/%dms' % (kind, ms))
            kind, ms = challenge(host)
            http_r.append('%s/%dms' % (kind, ms))
            time.sleep(1.2)
        emit('RATE', host=host, attempts=ATTEMPTS,
             tcp=tcp_r, tls=tls_r, challenge=http_r,
             tcp_ok=sum(1 for x in tcp_r if x.startswith('ok')),
             tls_ok=sum(1 for x in tls_r if x.startswith('ok')),
             challenge_ok=sum(1 for x in http_r if x.startswith('complete')))

    # Control on the same runner: Cloudflare-fronted panel must stay stable.
    control = []
    for _ in range(3):
        try:
            with requests.Session() as session:
                session.trust_env = False
                response = session.get('https://' + PANEL + '/api/v1/guest/comm/config',
                                       timeout=(4, 8))
            control.append('HTTP_%d' % response.status_code)
        except Exception as error:
            control.append(type(error).__name__)
    emit('CONTROL', panel=control)


if __name__ == '__main__':
    main()
