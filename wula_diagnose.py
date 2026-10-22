"""Clean first-request test: does a browser TLS fingerprint avoid the ban?

Hypothesis: the origin bans the IP on the FIRST request if that request carries
a non-browser TLS fingerprint (OpenSSL via requests/urllib). If so, a runner that
sends its very first request with a Chrome fingerprint should get through.

Discipline: absolutely nothing network-touching happens before the first
challenge request. No ipify, no TCP probe, no DNS debug.
"""
import json
import time

from curl_cffi import requests as cr

HOST = 'wulass.org'
URL = 'https://' + HOST + '/fd0fb2130e/challenge'


def emit(kind, **kw):
    print('CLEAN_' + kind, json.dumps(kw, ensure_ascii=False), flush=True)


def main():
    # ---- attempt 1: very first outbound request of this job, Chrome TLS ----
    started = time.monotonic()
    try:
        with cr.Session(impersonate='chrome131', trust_env=False) as session:
            response = session.post(
                URL,
                headers={'Origin': 'https://' + HOST, 'Referer': 'https://' + HOST + '/'},
                timeout=(6, 12))
        elapsed = round((time.monotonic() - started) * 1000)
        body = response.content
        complete = False
        fields = []
        try:
            payload = response.json()
            fields = list(payload) if isinstance(payload, dict) else []
            complete = bool(isinstance(payload, dict) and payload.get('token')
                            and payload.get('challenge') and payload.get('instrumentation'))
        except ValueError:
            pass
        emit('CHROME_FIRST', http=response.status_code, bytes=len(body),
             complete=complete, fields=fields, ms=elapsed)
    except Exception as error:
        emit('CHROME_FIRST', error=type(error).__name__,
             detail=str(error)[:200], ms=round((time.monotonic() - started) * 1000))
        return

    if not complete:
        emit('RESULT', verdict='chrome_first_also_blocked')
        return

    # ---- if challenge worked, the whole signup flow may now be possible ----
    # Redeem on the SAME session keeps us at one TCP connection (keep-alive).
    emit('RESULT', verdict='chrome_first_works')
    emit('NEXT', note='challenge obtained; full signup could be attempted here')


if __name__ == '__main__':
    main()
