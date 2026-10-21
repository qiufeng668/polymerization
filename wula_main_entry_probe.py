"""Public API only: test the real host returned by /cdn-cgi/trace. No registration."""
import hashlib,json,socket,time
import requests
from curl_cffi import requests as cr
HOST='main.wulavpn.com';BASE='https://'+HOST
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
def emit(kind,**kw):print(kind,json.dumps(kw,ensure_ascii=False),flush=True)
def detail(r):
    result={'status':r.status_code,'bytes':len(r.content),'type':r.headers.get('content-type'),'cf':r.headers.get('cf-ray'),'hash':hashlib.sha256(r.content).hexdigest()[:12]}
    try:
        j=r.json();result['keys']=list(j) if isinstance(j,dict) else [];result['challenge']=bool(isinstance(j,dict) and j.get('token') and j.get('challenge') and j.get('instrumentation'))
        if isinstance(j,dict) and isinstance(j.get('data'),dict):
            d=j['data'];result['config']={k:d[k] for k in ('app_url','recaptcha_site_key','recaptcha_enable') if k in d}
    except ValueError:pass
    return result
for host in (HOST,'wula001.com'):
    try:
        emit('ENTRY_DNS',host=host,ips=sorted({x[4][0] for x in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)}))
        with socket.create_connection((host,443),timeout=4) as conn:emit('ENTRY_TCP',host=host,ok=True,peer=conn.getpeername()[0])
    except Exception as e:emit('ENTRY_TCP',host=host,ok=False,error=type(e).__name__)
for label,factory in [('requests',requests.Session),('chrome',lambda:cr.Session(impersonate='chrome131',trust_env=False))]:
    with factory() as s:
        s.trust_env=False;s.headers.update({'User-Agent':UA,'Origin':BASE,'Referer':BASE+'/'})
        for path in ('/cdn-cgi/trace','/api/v1/guest/comm/config','/fd0fb2130e/challenge'):
            try:
                r=s.post(BASE+path,json={},timeout=(4,7)) if path.endswith('challenge') else s.get(BASE+path,timeout=(4,7))
                d=detail(r)
                if path.endswith('trace'):
                    trace=dict(line.split('=',1) for line in r.text.splitlines() if '=' in line)
                    d['trace']={k:v for k,v in trace.items() if k in ('h','loc','colo','http','warp','tls')}
                emit('ENTRY_RESPONSE',transport=label,path=path,**d)
            except Exception as e:emit('ENTRY_RESPONSE',transport=label,path=path,error=type(e).__name__)
