"""Finite real-host/SNI/path comparison. No redemption, no registration."""
import hashlib,json,re,socket,time
import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.util import connection
START=time.monotonic()
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
def emit(k,**data):print(k,json.dumps(data,ensure_ascii=False),flush=True)
class RouteAdapter(HTTPAdapter):
    def __init__(self,ip,**kw):self.ip=ip;super().__init__(**kw)
    def init_poolmanager(self,connections,maxsize,block=False,**kw):
        ip=self.ip
        class Conn(HTTPSConnection):
            def _new_conn(self):return connection.create_connection((ip,self.port),self.timeout,source_address=self.source_address,socket_options=self.socket_options)
        class Pool(HTTPSConnectionPool):ConnectionCls=Conn
        super().init_poolmanager(connections,maxsize,block=block,**kw)
        self.poolmanager.pool_classes_by_scheme={**self.poolmanager.pool_classes_by_scheme,'https':Pool}
def probe(url,ip=None,host_header=None,payload=None):
    host=url.split('/')[2]
    with requests.Session() as s:
        s.trust_env=False;s.headers.update({'User-Agent':UA,'Origin':'https://'+host,'Referer':'https://'+host+'/'})
        if host_header:s.headers['Host']=host_header
        if ip:s.mount('https://'+host+'/',RouteAdapter(ip))
        try:
            r=s.post(url,json=payload,timeout=(3,5),allow_redirects=False)
            fields=[];complete=False
            try:
                j=r.json();fields=list(j) if isinstance(j,dict) else [];complete=bool(isinstance(j,dict) and j.get('token') and j.get('challenge') and j.get('instrumentation'))
            except ValueError:pass
            emit('ORIGIN',url=url,route=ip,host_header=host_header,status=r.status_code,size=len(r.content),type=r.headers.get('content-type'),cf=r.headers.get('cf-ray'),complete=complete,fields=fields,hash=hashlib.sha256(r.content).hexdigest()[:12])
        except Exception as e:emit('ORIGIN',url=url,route=ip,host_header=host_header,error=type(e).__name__,detail=str(e)[:150])
for host in ('wula001.com','wulass.org','windowsv1.com'):
    probe('https://'+host+'/fd0fb2130e/challenge',payload={})
for host in ('wula001.com','wulass.org'):
    for ip in ('104.21.32.245','172.67.188.80'):
        probe('https://'+host+'/fd0fb2130e/challenge',ip=ip,payload={})
for host_header in ('wula001.com','wulass.org'):
    probe('https://main.wulavpn.com/fd0fb2130e/challenge',host_header=host_header,payload={})
for path in ('/fd0fb2130e/challenge/','/api/fd0fb2130e/challenge','/challenge'):
    probe('https://main.wulavpn.com'+path,payload={})
emit('ORIGIN_DONE',seconds=round(time.monotonic()-START,2))
