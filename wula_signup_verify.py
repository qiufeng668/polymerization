"""Verify the Chrome-fingerprint registration path on a GitHub runner.
One account at most. Saves only to local workspace; never prints credentials.
"""
import importlib.util, json, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('wula_verify', ROOT / 'plugins/wula.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


def emit(kind, **kw):
    print('VERIFY_' + kind, json.dumps(kw, ensure_ascii=False), flush=True)


def main():
    w.PROXY = None
    w._DEADLINE = time.monotonic() + 200
    emit('CONFIG', impersonate=w.IMPERSONATE, captcha=w.CAPTCHA_BASE,
         panel=w.PANEL_BASE, subscribe=w.SUBSCRIBE_BASE)

    started = time.monotonic()
    try:
        account = w._register_one(w._rand_email_unique(), w._rand_password())
    except Exception as error:
        emit('REGISTER', ok=False, error_type=type(error).__name__,
             detail=w._error_text(error),
             seconds=round(time.monotonic() - started, 1))
        return
    emit('REGISTER', ok=True, seconds=round(time.monotonic() - started, 1))

    text, nodes, error = w._fetch_nodes(account['token'])
    emit('SUBSCRIBE', ok=bool(nodes), nodes=len(nodes), error=error)

    if nodes:
        w._save_bank(account)
        emit('SAVED', note='account cached locally in runner workspace (not pushed)')


if __name__ == '__main__':
    main()
