#!/usr/bin/env python3
"""Inject expired cached credentials only into this disposable runner workspace."""
import argparse,json,os,time
from pathlib import Path
from urllib.parse import urlsplit,parse_qs
p=argparse.ArgumentParser();p.add_argument('--prepare',action='store_true');p.add_argument('--assert-result',action='store_true');p.add_argument('--push-bank',action='store_true');a=p.parse_args()
bank=Path('vault_repo/wula_bank.json') if Path('vault_repo').exists() else Path('wula_bank.json')
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
    saved=json.loads(bank.read_text())
    assert saved and saved[0].get('token')==fresh[0].get('token'), 'new account not cached in runner vault'
    assert time.time()-float(saved[0].get('ts') or 0)<300, 'cached account timestamp is stale'
    print('SANDBOX_RESULT registered=%d nodes=%d new_account_cached=1'%(len(fresh),sum(bool(x.strip()) for x in nodes.read_text().splitlines())),flush=True)
if a.push_bank:
    import base64,urllib.parse,requests
    token=os.environ.get('GH_TOKEN')
    assert token,'GH_TOKEN is required for the isolated bank write'
    old=json.loads(bank.read_text())
    fresh=json.loads((Path('/tmp/wula-expiry-output')/'accounts.json').read_text())
    created=[x for x in fresh if x.get('token') and not x.get('bank_fallback')]
    assert len(created)==1,'expected exactly one freshly registered account'
    merged=[created[0]]+[x for x in old if x.get('token')!=created[0]['token']]
    merged=merged[:10]
    api='https://api.github.com/repos/qiufeng668/polymerization-1/contents/wula_bank.json'
    headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}
    for attempt in range(3):
        r=requests.get(api,params={'ref':'main'},headers=headers,timeout=(5,18));r.raise_for_status();sha=r.json()['sha']
        body={'message':'Refresh one Wula account on ARM runner','content':base64.b64encode(json.dumps(merged,ensure_ascii=False,indent=1).encode()).decode(),'sha':sha,'branch':'main'}
        w=requests.put(api,json=body,headers=headers,timeout=(5,22))
        if w.status_code==200:
            print('BANK_REFRESHED count=%d new_entry=1' % len(merged),flush=True);break
        if w.status_code!=409 or attempt==2:raise RuntimeError('bank update HTTP %s'%w.status_code)
    verify=requests.get(api,params={'ref':'main'},headers=headers,timeout=(5,18));verify.raise_for_status()
    check=json.loads(base64.b64decode(verify.json()['content']))
    assert check and check[0].get('token')==created[0]['token'],'fresh account missing after bank write'
    print('BANK_VERIFY fresh_entry_first=1 count=%d' % len(check),flush=True)
