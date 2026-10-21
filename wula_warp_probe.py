"""Bounded anonymous WARP path test. Never registers at Wula or prints keys/tokens.
Python 3.11 | requests[socks] | wgcf 2.3.1 and wireproxy 1.1.3.
"""
import configparser,hashlib,importlib.util,ipaddress,json,os,re,socket,subprocess,tempfile,time
from pathlib import Path
import requests
ROOT=Path(__file__).resolve().parent
START=time.monotonic()

def emit(kind,**data):print(kind,json.dumps(data,ensure_ascii=False),flush=True)
def safe_error(e):
    text=str(e)
    text=re.sub(r'(?i)(token=)[^&\s]+',r'\1[hidden]',text)
    return text[:280]
def digest_response(r):
    complete=False
    try:
        j=r.json();complete=isinstance(j,dict) and bool(j.get('token') and j.get('challenge') and j.get('instrumentation'))
    except Exception:pass
    return {'status':r.status_code,'type':r.headers.get('content-type'),'bytes':len(r.content),'complete':complete,'hash':hashlib.sha256(r.content).hexdigest()[:12]}

def tcp_ready(port):
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=.4):return True
    except OSError:return False

def main():
    with tempfile.TemporaryDirectory(prefix='wula-warp-') as tmp:
        folder=Path(tmp)
        # The anonymous WARP device is ephemeral in this runner, one registration only.
        r=subprocess.run(['wgcf','register','--accept-tos'],cwd=folder,capture_output=True,timeout=55)
        account=folder/'wgcf-account.toml'
        emit('WARP_REGISTER',exit=r.returncode,account_present=account.exists())
        if not account.exists():return
        r=subprocess.run(['wgcf','generate'],cwd=folder,capture_output=True,timeout=25)
        profile=folder/'wgcf-profile.conf'
        emit('WARP_PROFILE',exit=r.returncode,profile_present=profile.exists())
        if not profile.exists():return
        original=profile.read_text()
        for endpoint in ('162.159.192.1:2408','162.159.193.10:2408','engage.cloudflareclient.com:2408'):
            if time.monotonic()-START>220:break
            text=re.sub(r'(?m)^Endpoint\s*=.*$', 'Endpoint = '+endpoint, original)
            # wireproxy handles AllowedIPs internally; both v4/v6 addresses remain intact.
            text+='\n[Socks5]\nBindAddress = 127.0.0.1:19081\n'
            config=folder/'wireproxy.conf';config.write_text(text)
            log=folder/'wireproxy.log'
            with log.open('w') as out:
                process=subprocess.Popen(['wireproxy','-c',str(config)],stdout=out,stderr=subprocess.STDOUT)
            try:
                for _ in range(20):
                    if process.poll() is not None:break
                    if tcp_ready(19081):break
                    time.sleep(.2)
                emit('WARP_CORE',endpoint=endpoint,running=process.poll() is None,port=tcp_ready(19081))
                if process.poll() is not None:continue
                with requests.Session() as session:
                    session.trust_env=False
                    session.proxies={'http':'socks5h://127.0.0.1:19081','https':'socks5h://127.0.0.1:19081'}
                    session.headers.update({'User-Agent':'Mozilla/5.0','Origin':'https://wula001.com','Referer':'https://wula001.com/'})
                    try:
                        r=session.get('https://www.cloudflare.com/cdn-cgi/trace',timeout=(6,10));r.raise_for_status()
                        trace=dict(line.split('=',1) for line in r.text.splitlines() if '=' in line)
                        emit('WARP_CONTROL',endpoint=endpoint,status=r.status_code,warp=trace.get('warp'),location=trace.get('loc'),egress_hash=hashlib.sha256(trace.get('ip','').encode()).hexdigest()[:12])
                        if trace.get('warp') not in ('on','plus'):continue
                    except Exception as e:
                        emit('WARP_CONTROL',endpoint=endpoint,error=type(e).__name__,detail=safe_error(e));continue
                    for host in ('wula001.com','wulass.org'):
                        try:
                            r=session.post('https://'+host+'/fd0fb2130e/challenge',json={},timeout=(5,10))
                            result=digest_response(r);emit('WARP_TARGET',host=host,**result)
                            if result['complete']:
                                emit('WORKING_ROUTE',kind='warp',endpoint=endpoint,host=host)
                                try:
                                    bank=json.loads((ROOT/'vault_repo/wula_bank.json').read_text())
                                    r=session.get('https://windowsv1.com/s/',params={'token':bank[0]['token']},headers={'User-Agent':'clash-verge/v1.3.8'},timeout=(5,12))
                                    import yaml
                                    data=yaml.safe_load(r.text);count=len(data.get('proxies',[])) if isinstance(data,dict) else 0
                                    emit('WARP_SUBSCRIPTION',status=r.status_code,nodes=count)
                                except Exception as e:emit('WARP_SUBSCRIPTION',error=type(e).__name__)
                                return
                        except Exception as e:emit('WARP_TARGET',host=host,error=type(e).__name__,detail=safe_error(e))
            finally:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill()
        emit('WARP_RESULT',working=False,seconds=round(time.monotonic()-START,1))

if __name__=='__main__':
    try:main()
    except subprocess.TimeoutExpired as e:emit('WARP_TOOL_TIMEOUT',command=e.cmd[0])
