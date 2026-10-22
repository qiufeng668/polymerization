"""Read-only CI network diagnosis. No registration; no token/node secrets in logs."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import time
import platform
import ssl
import requests
import main_engine

ROOT = Path(__file__).resolve().parent

def main():
    print('runner',platform.system(),platform.machine(),'TLS',ssl.OPENSSL_VERSION,flush=True)
    summary={'runner':platform.system(), 'challenge':False, 'subscription_nodes':0}
    print('proxy environment variable names:', [k for k in os.environ if 'proxy' in k.lower()], flush=True)
    for host in ('wula001.com', 'windowsv1.com'):
        try:
            print('DNS', host, sorted({i[4][0] for i in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)}), flush=True)
        except Exception as ex:
            print('DNS',host,type(ex).__name__, flush=True)
    with requests.Session() as s:
        s.trust_env=False
        for host in ('wula001.com','windowsv1.com'):
            try:
                j=s.get('https://dns.google/resolve',params={'name':host,'type':'A'},timeout=(5,8)).json()
                print('DoH',host,[i['data'] for i in j.get('Answer',[]) if i['type']==1],flush=True)
            except Exception as ex:
                print('DoH',host,type(ex).__name__,flush=True)
        for url in ('https://www.gstatic.com/generate_204','https://wula001.com/','https://windowsv1.com/'):
            t=time.monotonic()
            try:
                r=s.get(url,timeout=(8,8))
                print('GET',url,r.status_code,'seconds',round(time.monotonic()-t,2),flush=True)
            except Exception as ex:
                print('GET',url,type(ex).__name__,'seconds',round(time.monotonic()-t,2),flush=True)
        t=time.monotonic()
        try:
            r=s.post('https://wula001.com/fd0fb2130e/challenge',json={},timeout=(8,8))
            j=r.json()
            summary['challenge']=bool(r.ok and isinstance(j,dict) and j.get('token') and j.get('challenge') and j.get('instrumentation'))
            print('challenge',r.status_code,'fields',list(j) if isinstance(j,dict) else 'invalid','seconds',round(time.monotonic()-t,2),flush=True)
        except Exception as ex:
            print('challenge',type(ex).__name__,'seconds',round(time.monotonic()-t,2),flush=True)
    spec=importlib.util.spec_from_file_location('wula',ROOT/'plugins/wula.py')
    w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
    bank_path=ROOT/'vault_repo/wula_bank.json'
    bank=json.loads(bank_path.read_text()) if bank_path.exists() else []
    print('bank entries',len(bank),flush=True)
    for i,account in enumerate(bank[:2]):
        t=time.monotonic()
        text,nodes,error=w._fetch_nodes(account.get('token',''))
        print('subscription account',i,'nodes',len(nodes),'error',error,'seconds',round(time.monotonic()-t,2),flush=True)
        summary['subscription_nodes']=max(summary['subscription_nodes'],len(nodes))
        if nodes:
            alive=main_engine.speedtest_modern_nodes(nodes)
            print('subscription modern HTTPS verified',len(alive) if alive is not None else None,flush=True)
            break
    original_getaddrinfo=socket.getaddrinfo
    for edge in ('104.21.1.1','172.67.1.1','104.16.132.229'):
        def route(host,port,*args,**kwargs):
            return original_getaddrinfo(edge if host in ('wula001.com','windowsv1.com') else host,port,*args,**kwargs)
        socket.getaddrinfo=route
        edge_ok=False
        with requests.Session() as s:
            s.trust_env=False
            s.headers.update({'User-Agent':w._UAS[0],'referer':w.BASE+'/','origin':w.BASE})
            try:
                r=s.post(w.BASE+'/fd0fb2130e/challenge',json={},timeout=(5,10))
                try:
                    j=r.json()
                except ValueError:
                    j=None
                edge_ok=bool(r.ok and isinstance(j,dict) and j.get('token') and j.get('challenge') and j.get('instrumentation'))
                snippet=' '.join(r.text[:180].split())
                print('EDGE',edge,'challenge',r.status_code,'ctype',r.headers.get('content-type'),'server',r.headers.get('server'),'complete',edge_ok,'body',snippet,flush=True)
            except Exception as ex:
                print('EDGE',edge,'challenge',type(ex).__name__,flush=True)
            edge_nodes=0
            if bank:
                try:
                    r=s.get('https://windowsv1.com/s/',params={'token':bank[0]['token']},headers={'User-Agent':'clash-verge/v1.3.8'},timeout=(5,10))
                    cfg=__import__('yaml').safe_load(r.text)
                    edge_nodes=len(cfg.get('proxies',[])) if isinstance(cfg,dict) else 0
                    print('EDGE',edge,'subscription',r.status_code,'config rows',edge_nodes,flush=True)
                except Exception as ex:
                    print('EDGE',edge,'subscription',type(ex).__name__,flush=True)
            if edge_ok and edge_nodes:
                summary.update({'edge':edge,'edge_challenge':True,'edge_subscription_rows':edge_nodes})
                break
    socket.getaddrinfo=original_getaddrinfo
    print('DIAG_SUMMARY',json.dumps(summary),flush=True)

if __name__=='__main__':
    main()
