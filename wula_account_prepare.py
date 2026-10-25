#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prepare exactly one valid Wula account on an ARM runner, then publish the bank.

Design:
  * Reads the private bank (one account only).
  * Reuses the account while it has more than RENEW_BEFORE_HOURS left.
  * Otherwise registers ONE new account and verifies its subscription first.
  * On any failure the existing private bank is left untouched.
  * Only wula_bank.json is written; no nodes are pushed.
"""
import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PRIVATE_REPO = 'qiufeng668/polymerization-1'
RENEW_BEFORE_HOURS = 3


def log(message):
    print(message, flush=True)


def random_delay(attempt):
    import random
    return random.uniform(3, 6) * attempt


def github(token):
    import requests
    session = requests.Session()
    session.headers.update({'Authorization': 'Bearer ' + token,
                            'Accept': 'application/vnd.github+json',
                            'X-GitHub-Api-Version': '2022-11-28'})
    return session


def load_remote_bank(session):
    url = 'https://api.github.com/repos/%s/contents/wula_bank.json' % PRIVATE_REPO
    response = session.get(url, params={'ref': 'main'}, timeout=(6, 25))
    response.raise_for_status()
    payload = response.json()
    rows = json.loads(base64.b64decode(payload['content']).decode('utf-8'))
    return (rows if isinstance(rows, list) else []), payload['sha']


def save_remote_bank(session, account):
    url = 'https://api.github.com/repos/%s/contents/wula_bank.json' % PRIVATE_REPO
    for _ in range(3):
        _, sha = load_remote_bank(session)
        body = {'message': 'Refresh one Wula account from ARM runner',
                'content': base64.b64encode(json.dumps([account], ensure_ascii=False, indent=1).encode()).decode(),
                'sha': sha, 'branch': 'main'}
        response = session.put(url, json=body, timeout=(6, 25))
        if response.status_code == 200:
            rows, _ = load_remote_bank(session)
            if rows and rows[0].get('token') == account.get('token'):
                return True
            raise RuntimeError('bank write verified but token mismatch')
        if response.status_code != 409:
            raise RuntimeError('bank write HTTP %d' % response.status_code)
        time.sleep(2)
    raise RuntimeError('bank write conflicted repeatedly')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--token', default=os.environ.get('GIT_TOKEN') or os.environ.get('GITHUB_TOKEN'))
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--force', action='store_true', help='ignore reuse window and register once')
    args = parser.parse_args()
    if not args.token:
        raise SystemExit('missing GIT_TOKEN')

    sys.path.insert(0, str(ROOT / 'plugins'))
    import wula
    wula.PROXY = None
    wula._DEADLINE = time.monotonic() + 300

    session = github(args.token)
    rows, _ = load_remote_bank(session)
    log('BANK_ENTRIES=%d' % len(rows))

    for entry in ([] if args.force else rows[:1]):
        if not isinstance(entry, dict):
            continue
        ok, reason = wula._bank_account_usable(entry)
        age_h = (time.time() - float(entry.get('ts') or 0)) / 3600 if entry.get('ts') else None
        log('BANK_STATUS=%s age_hours=%s' % ('active' if ok else reason,
                                            round(age_h, 1) if age_h is not None else None))
        if ok and age_h is not None and age_h < 24 - RENEW_BEFORE_HOURS:
            log('DECISION=reuse age_within_window=1')
            return 0

    log('DECISION=register reason=expired_or_near_expiry')
    account = None
    last = None
    for attempt in range(1, 4):
        try:
            log('ATTEMPT=%d' % attempt)
            candidate = wula._register_one(wula._rand_email_unique(), wula._rand_password())
            text, nodes, error = wula._fetch_nodes(candidate['token'])
            if error or not nodes:
                raise RuntimeError('subscription invalid: %s' % (error or 'empty'))
            log('REGISTERED=1 nodes=%d attempt=%d' % (len(nodes), attempt))
            account = candidate
            break
        except Exception as exc:
            last = exc
            log('ATTEMPT_FAILED=%d %s' % (attempt, wula._error_text(exc)))
            if attempt < 3:
                time.sleep(random_delay(attempt))
    if account is None:
        raise RuntimeError('all registration attempts failed: %s' % wula._error_text(last))
    account['ts'] = int(time.time())
    if args.dry_run:
        log('DRY_RUN=1 skip_bank_write')
        return 0
    save_remote_bank(session, account)
    log('BANK_WRITTEN=1 entries=1')


if __name__ == '__main__':
    main()
