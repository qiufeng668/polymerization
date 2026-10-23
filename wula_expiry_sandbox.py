#!/usr/bin/env python3
"""Inject expired cached credentials only into this disposable runner workspace."""
import argparse,json,os,time
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
p=argparse.ArgumentParser();p.add_argument('--prepare',action='store_true');p.add_argument('--assert-result',action='store_true');a=p.parse_args()
bank=Path('vault_repo/wula_bank.json')
rows=json.loads(bank.read_text())
assert rows and rows[0].get('email') and rows[0].get('password') and rows[0].get('token'), 'private bank entry incomplete'
if a.prepare:
    rows[0]['ts']=int(time.time()-48*3600)
    os.makedirs('vault_repo',exist_ok=True)
    bank.write_text(json.dumps(rows,ensure_ascii=False))
    print('SANDBOX_CACHE prepared=1 expired_ts=1 bank_entries=%d'%len(rows),flush=True)
if a.assert_result:
    out=Path('/tmp/wula-expiry-output')
    nodes=out/'nodes.txt'; accts=out/'accounts.json'
    assert nodes.exists() and any(x.strip() for x in nodes.read_text().splitlines()), 'no fresh node output'
    data=json.loads(accts.read_text()) if accts.exists() else []
    assert data, 'no account result record'
    fresh=[x for x in data if not x.get('bank_fallback')]
    assert fresh, 'run reused an expired cached account instead of registering'
    print('SANDBOX_RESULT registered=%d nodes=%d'%(len(fresh),sum(bool(x.strip()) for x in nodes.read_text().splitlines())),flush=True)
