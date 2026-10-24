#!/usr/bin/env python3
"""Assert the production plugin replaced an expired private bank with one fresh account."""
import json,time
from pathlib import Path
bank=json.loads(Path('vault_repo/wula_bank.json').read_text())
accounts=json.loads(Path('/tmp/wula-rollover-output/accounts.json').read_text())
nodes=[x for x in Path('/tmp/wula-rollover-output/nodes.txt').read_text().splitlines() if x.strip()]
fresh=[x for x in accounts if x.get('token') and not x.get('bank_fallback')]
assert len(fresh)==1,'expected exactly one new account from expired bank'
assert len(bank)==1,'single-account bank must contain exactly one entry'
assert bank[0].get('token')==fresh[0].get('token'),'bank was not atomically replaced by fresh token'
assert 0 <= time.time()-float(bank[0].get('ts') or 0) < 300,'fresh account timestamp missing/stale'
assert len(nodes)==31,'expected verified 31-node subscription, got %d'%len(nodes)
print('ROLLOVER_SANDBOX_OK registered=1 bank_entries=1 nodes=31')
