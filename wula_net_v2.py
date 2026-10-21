"""Read-only hosted transport diagnosis. No redeem/register, no credentials printed.
Runtime Python 3.11, deps requests curl_cffi pyyaml.
"""
import hashlib,json,os,socket,time
from pathlib import Path
from urllib.parse import urlsplit
import requests
from curl_cffi import requests as cr
from curl_cffi import CurlOpt, CurlHttpVersion
START=time.monotonic()
HOSTS=['wula001.com','wulass.org','wulavpn.com','windowsv1.com']
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
def emit(kind,**kw):
    print(kind,json.dumps(kw,ensure_ascii=False),flush=True)
def describe(r,label):
    complete=False;fields=[]
    try:
        j=r.json()
        if isinstance(j,dict):
            fields=list(j)
            complete=bool(j.get('token') and j.get('challenge') and j.get('instrumentation'))
    except Exception:pass
    emit('RESPONSE',label=label,status=r.status_code,type=r.headers.get('content-type'),server=r.headers.get('server'),cf=r.headers.get('cf-ray'),cfmitigated=r.headers.get('cf-mitigated'),size=len(r.content),hash=hashlib.sha256(r.content).hexdigest()[:12],complete=complete,fields=fields)
    return complete

def main():
    with requests.Session() as s:
        s.trust_env=False;s.headers['User-Agent']=UA
        for host in HOSTS:
            try:
                ips=sorted({x[4][0] for x in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)})
                emit('DNS',host=host,ips=ips)
            except Exception as e:emit('DNS',host=host,error=type(e).__name__)
        for host in HOSTS:
            try:
                s.headers.update({'Origin':'https://'+host,'Referer':'https://'+host+'/'})
                if host in ('wula001.com','wulass.org'):
                    r=s.post('https://'+host+'/fd0fb2130e/challenge',json={},timeout=(3,4))
                else:r=s.get('https://'+host+'/',timeout=(3,4),allow_redirects=False)
                describe(r,'requests '+host)
            except Exception as e:emit('REQUESTS',host=host,error=type(e).__name__)
    # TCP-only control: no TLS and therefore no TLS/JS fingerprint at this stage.
    for host in HOSTS:
        t=time.monotonic()
        try:
            with socket.create_connection((host,443),timeout=3) as conn:
                emit('TCP',host=host,ok=True,peer=conn.getpeername()[0],seconds=round(time.monotonic()-t,2))
        except Exception as e:emit('TCP',host=host,ok=False,error=type(e).__name__,seconds=round(time.monotonic()-t,2))
    # Real peer IP is recorded by libcurl so local transparent-routing artifacts are visible.
    for host in HOSTS:
        for edge in (None,'104.21.1.1','104.16.132.229','192.0.2.1'):
            if time.monotonic()-START>155:break
            label='chrome131 '+host+' '+(edge or 'system')
            try:
                options={CurlOpt.RESOLVE:[f'{host}:443:{edge}']} if edge else {}
                with cr.Session(impersonate='chrome131',trust_env=False,curl_options=options) as s:
                    s.headers.update({'Origin':'https://'+host,'Referer':'https://'+host+'/'})
                    if host in ('wula001.com','wulass.org'):
                        r=s.post('https://'+host+'/fd0fb2130e/challenge',json={},timeout=(3,5))
                    else:r=s.get('https://'+host+'/',timeout=(3,5),allow_redirects=False)
                    complete=describe(r,label)
                    emit('PEER',label=label,peer=getattr(r,'primary_ip',None),local=getattr(r,'local_ip',None))
                    if complete:
                        emit('CANDIDATE',host=host,route=edge or 'system',transport='curl_cffi')
            except Exception as e:emit('CURL',label=label,error=type(e).__name__)
    for impersonation in (None,'chrome131'):
        for version in (CurlHttpVersion.V1_1,CurlHttpVersion.V2_0):
            try:
                with cr.Session(impersonate=impersonation,trust_env=False,http_version=version) as s:
                    r=s.post('https://wula001.com/fd0fb2130e/challenge',json={},timeout=(3,4),headers={'User-Agent':UA,'Origin':'https://wula001.com','Referer':'https://wula001.com/'})
                    describe(r,'fingerprint '+str(impersonation)+' http '+str(version))
            except Exception as e:emit('FINGERPRINT',impersonation=impersonation,http=str(version),error=type(e).__name__)
    # Certificate-valid origin/SNI routing with an HTTP endpoint, to distinguish HTTPS-only routing.
    for host in ('wula001.com','wulass.org','windowsv1.com'):
        if time.monotonic()-START>170:break
        try:
            r=requests.get('http://'+host+'/',headers={'User-Agent':UA},timeout=(3,4),allow_redirects=False)
            describe(r,'http '+host);emit('REDIRECT',host=host,location=r.headers.get('location','')[:150])
        except Exception as e:emit('HTTP',host=host,error=type(e).__name__)
    emit('FINISHED',seconds=round(time.monotonic()-START,2))
if __name__=='__main__':main()
