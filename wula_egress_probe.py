"""Read-only outbound-path diagnosis on GitHub. Never registers accounts or writes vault.
Python 3.11 | requests pyyaml curl_cffi | mihomo v1.19.32.
"""
import collections,hashlib,importlib.util,ipaddress,json,os,re,subprocess,tempfile,time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor,as_completed
import requests,yaml
from curl_cffi import requests as cr
from curl_cffi import CurlOpt
ROOT=Path(__file__).resolve().parent
START=time.monotonic();BUDGET=480
CONTROL='https://www.gstatic.com/generate_204'
API='http://127.0.0.1:19090'
PROXY='http://127.0.0.1:18980'
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

def emit(kind,**data):
    print(kind,json.dumps(data,ensure_ascii=False),flush=True)

def response_summary(r):
    fields=[];complete=False
    try:
        j=r.json()
        if isinstance(j,dict):
            fields=list(j)
            complete=bool(j.get('token') and j.get('challenge') and j.get('instrumentation'))
    except Exception:pass
    title=re.search(r'<title[^>]*>(.*?)</title>',r.text,re.I|re.S)
    error=re.search(r'(?:Error\s*(?:code\s*)?|error code:|data-translate="error")\D{0,12}(10\d\d|5\d\d)',r.text,re.I)
    return {'status':r.status_code,'bytes':len(r.content),'hash':hashlib.sha256(r.content).hexdigest()[:12],
            'type':r.headers.get('content-type'),'cf':r.headers.get('cf-ray'),'complete':complete,'fields':fields,
            'title':re.sub('<[^>]+>','',title.group(1)).strip()[:120] if title else None,
            'error_code':error.group(1) if error else None}

def load_nodes():
    result=[]
    vault=ROOT/'vault_repo'
    # Prefer fresh Alice source YAML to avoid losing Reality parameters in exported pools.
    try:
        bank=json.loads((vault/'alice_bank.json').read_text())
        link=bank[0]['sub_link']
        if re.fullmatch(r'https://sub\.harnesscom\.com/sub/[A-Za-z0-9_.-]+',link):
            r=requests.get(link+'/clash_meta',headers={'User-Agent':'clash-verge/v1.3.8'},timeout=(4,12));r.raise_for_status()
            cfg=yaml.safe_load(r.text)
            fresh=cfg.get('proxies',[]) if isinstance(cfg,dict) else []
            result.extend(fresh);emit('SOURCE',name='alice-fresh',count=len(fresh))
    except Exception as e:emit('SOURCE',name='alice-fresh',error=type(e).__name__)
    for name in ('clash.yaml','wula_pool.json'):
        try:
            if name.endswith('.yaml'):
                cfg=yaml.safe_load((vault/name).read_text());nodes=cfg.get('proxies',[]) if isinstance(cfg,dict) else []
            else:
                cfg=json.loads((vault/name).read_text());nodes=list((cfg.get('nodes') or {}).values())
            result.extend(nodes);emit('SOURCE',name=name,count=len(nodes))
        except Exception as e:emit('SOURCE',name=name,error=type(e).__name__)
    spec=importlib.util.spec_from_file_location('pool_engine',ROOT/'main_engine.py')
    engine=importlib.util.module_from_spec(spec);spec.loader.exec_module(engine)
    try:
        state=json.loads((vault/'cache_state.json').read_text())
        extra=[]
        for info in state.values():
            if isinstance(info,dict):
                for uri in info.get('nodes',[]):
                    node=engine.uri_to_clash_proxy(uri)
                    if node:extra.append(node)
        result.extend(extra);emit('SOURCE',name='plugin-cache',count=len(extra))
    except Exception as e:emit('SOURCE',name='plugin-cache',error=type(e).__name__)
    unique=[];seen=set()
    allowed={'vless','vmess','ss','trojan','hysteria2','anytls','tuic'}
    for raw in result:
        if not isinstance(raw,dict) or raw.get('type') not in allowed:continue
        if not raw.get('server') or not raw.get('port'):continue
        if any(x in str(raw.get('name','')) for x in ('剩余','到期','套餐','官网')):continue
        node={k:v for k,v in raw.items() if k not in ('name','egress','exit_ip')}
        fingerprint=hashlib.sha256(json.dumps(node,sort_keys=True,default=str).encode()).hexdigest()
        if fingerprint in seen:continue
        seen.add(fingerprint)
        node['name']='p'+str(len(unique)).zfill(4)
        unique.append(node)
    emit('POOL',count=len(unique),types=dict(collections.Counter(x['type'] for x in unique)))
    return unique

def config(nodes):
    return {'mixed-port':18980,'external-controller':'127.0.0.1:19090','allow-lan':False,
            'bind-address':'127.0.0.1','mode':'rule','log-level':'silent',
            'proxies':nodes,'proxy-groups':[{'name':'OUT','type':'select','proxies':[x['name'] for x in nodes]}],
            'rules':['MATCH,OUT']}

def validate(nodes,folder):
    if not nodes:return []
    path=folder/'validate.yaml';path.write_text(yaml.safe_dump(config(nodes),allow_unicode=True,sort_keys=False))
    r=subprocess.run(['mihomo','-t','-d',str(folder),'-f',str(path)],capture_output=True,timeout=12)
    if r.returncode==0:return nodes
    if len(nodes)==1:
        emit('CONFIG_INVALID',node=nodes[0]['name'],type=nodes[0]['type'])
        return []
    mid=len(nodes)//2
    return validate(nodes[:mid],folder)+validate(nodes[mid:],folder)

def delay(node):
    if time.monotonic()-START>BUDGET-90:return None
    try:
        r=requests.get(API+'/proxies/'+node['name']+'/delay',params={'url':CONTROL,'timeout':4500},timeout=(2,6))
        j=r.json()
        if r.status_code==200 and isinstance(j.get('delay'),(int,float)):
            return (j['delay'],node)
    except Exception:pass
    return None

def target_probe(node,bank):
    name=node['name'];kind=node['type']
    r=requests.put(API+'/proxies/OUT',json={'name':name},timeout=3);r.raise_for_status()
    session=requests.Session();session.trust_env=False;session.proxies={'http':PROXY,'https':PROXY}
    session.headers.update({'User-Agent':UA,'Origin':'https://wula001.com','Referer':'https://wula001.com/'})
    try:
        r=session.get(CONTROL,timeout=(3,5))
        emit('CONTROL',node=name,type=kind,status=r.status_code)
        if r.status_code!=204:return False
    except Exception as e:emit('CONTROL',node=name,type=kind,error=type(e).__name__);return False
    for host in ('wula001.com','wulass.org'):
        try:
            r=session.post('https://'+host+'/fd0fb2130e/challenge',json={},timeout=(4,7))
            result=response_summary(r);emit('TARGET',node=name,host=host,transport='requests',**result)
            if result['complete']:
                if bank:
                    try:
                        sub=session.get('https://windowsv1.com/s/',params={'token':bank[0].get('token','')},headers={'User-Agent':'clash-verge/v1.3.8'},timeout=(4,10));sub.raise_for_status()
                        cfg=yaml.safe_load(sub.text);count=len(cfg.get('proxies',[])) if isinstance(cfg,dict) else 0
                        emit('SUBSCRIPTION',node=name,status=sub.status_code,nodes=count)
                    except Exception as e:emit('SUBSCRIPTION',node=name,error=type(e).__name__)
                emit('WORKING_ROUTE',node=name,type=kind,host=host)
                return True
        except Exception as e:emit('TARGET',node=name,host=host,transport='requests',error=type(e).__name__)
    # Same egress, browser TLS; never change egress halfway through a proof.
    try:
        with cr.Session(impersonate='chrome131',proxy=PROXY,trust_env=False) as chrome:
            chrome.headers.update({'Origin':'https://wula001.com','Referer':'https://wula001.com/'})
            r=chrome.post('https://wula001.com/fd0fb2130e/challenge',json={},timeout=(4,7))
            result=response_summary(r);emit('TARGET',node=name,host='wula001.com',transport='chrome131',**result)
            if result['complete']:
                emit('WORKING_ROUTE',node=name,type=kind,host='wula001.com',chrome=True)
                return True
    except Exception as e:emit('TARGET',node=name,transport='chrome131',error=type(e).__name__)
    return False

def main():
    nodes=load_nodes()
    if not nodes:emit('RESULT',valid_nodes=0);return
    try:bank=json.loads((ROOT/'vault_repo/wula_bank.json').read_text())
    except Exception:bank=[]
    emit('ACCOUNT_CACHE',count=len(bank))
    with tempfile.TemporaryDirectory(prefix='wula-egress-') as temp:
        folder=Path(temp);nodes=validate(nodes,folder)
        emit('CONFIG_VALID',count=len(nodes))
        if not nodes:return
        conf=folder/'config.yaml';conf.write_text(yaml.safe_dump(config(nodes),allow_unicode=True,sort_keys=False))
        process=subprocess.Popen(['mihomo','-d',str(folder),'-f',str(conf)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(25):
                try:
                    if requests.get(API+'/version',timeout=.4).ok:break
                except Exception:pass
                time.sleep(.15)
            # A single core with bounded concurrency, rather than hundreds of forked cores.
            alive=[];done=0
            with ThreadPoolExecutor(max_workers=12) as pool:
                futures=[pool.submit(delay,node) for node in nodes]
                for future in as_completed(futures):
                    done+=1;value=future.result()
                    if value:alive.append(value)
                    if done%60==0:emit('PROGRESS',tested=done,neutral_alive=len(alive),seconds=round(time.monotonic()-START,1))
            alive.sort(key=lambda x:x[0])
            emit('NEUTRAL_RESULT',tested=done,alive=len(alive),types=dict(collections.Counter(n['type'] for _,n in alive)))
            working=False;tested=0
            for latency,node in alive[:18]:
                if time.monotonic()-START>BUDGET-40:break
                tested+=1;emit('TRY_ROUTE',node=node['name'],type=node['type'],latency=latency)
                if target_probe(node,bank):working=True;break
            emit('RESULT',working=working,target_tested=tested,neutral_alive=len(alive),seconds=round(time.monotonic()-START,1))
        finally:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill()
if __name__=='__main__':main()
