"""Check the real private Wula cache without printing node URIs or credentials."""
import base64
import collections
import importlib.util
import json
import os
import tempfile
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('wula_export_candidate', ROOT / 'main_engine.py')
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)
http = requests.Session()
http.headers.update({'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                     'Accept': 'application/vnd.github+json'})
base = 'https://api.github.com/repos/qiufeng668/polymerization-1/contents/'

def read(path):
    r = http.get(base + path, params={'ref': 'main'}, timeout=(5, 18))
    r.raise_for_status()
    return base64.b64decode(r.json()['content']).decode('utf-8')

state = json.loads(read('cache_state.json'))
wula_raw = state['wula.py']['nodes']
assert wula_raw
with tempfile.TemporaryDirectory() as tmp:
    plain = Path(tmp) / 'wula.txt'
    encoded = Path(tmp) / 'wula_base64.txt'
    count = engine.export_wula_only(wula_raw, str(plain), str(encoded))
    lines = [x for x in plain.read_text().splitlines() if x.strip()]
    decoded = base64.b64decode(encoded.read_bytes()).decode().splitlines()
    current_final = [x for x in read('nodes_plain.txt').splitlines() if 'wula' in engine.extract_original_name(x).lower()]
    assert count == len(lines) == len(decoded)
    assert lines == decoded
    assert len(lines) == 31, f'expected 31 unique Wula source nodes, got {len(lines)}'
    assert len(current_final) == 4, f'baseline expected 4 speed-passed Wula nodes, got {len(current_final)}'
    print('SANDBOX_WULA raw=%d unique_unfiltered=%d speed_filtered=%d' %
          (len(wula_raw), len(lines), len(current_final)))
    print('SANDBOX_PROTOCOLS', dict(collections.Counter(x.split(':', 1)[0] for x in lines)))
