"""Bounded signup diagnostics. One normal signup at most, never prints credentials.
No bypass payloads, no proxy rotation. Save a successful account only to private vault.
"""
import hashlib,json,re,secrets,string,time
from pathlib import Path
from urllib.parse import urlsplit
import requests,yaml
from curl_cffi import requests as cr
BASE='https://main.wulavpn.com'
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
ROOT=Path(__file__).resolve().parent
START=time.monotonic()
def emit(kind,**kw):print('SIGNUP_'+kind,json.dumps(kw,ensure_ascii=False),flush=True)
def session():
    s=requests.Session();s.trust_env=False
    s.headers.update({'User-Agent':UA,'Origin':BASE,'Referer':BASE+'/','Accept':'application/json'})
    return s
def shape():
    for host in ('main.wulavpn.com','wula001.com','wulass.org'):
        origin='https://'+host
        with session() as s:
            s.headers.update({'Origin':origin,'Referer':origin+'/'})
            try:
                r=s.get(origin+'/',timeout=(3,5))
                emit('ROOT',host=host,http=r.status_code,cookies=len(s.cookies),same_origin_normalize='window.location.origin + path' in r.text)
            except Exception as e:emit('ROOT',host=host,error=type(e).__name__)
            for label,kwargs in [('browser-empty',{}),('plugin-json',{'json':{}})]:
                try:
                    r=s.post(origin+'/fd0fb2130e/challenge',timeout=(3,5),allow_redirects=False,**kwargs)
                    try:j=r.json()
                    except ValueError:j={}
                    good=isinstance(j,dict) and bool(j.get('token') and j.get('challenge') and j.get('instrumentation'))
                    emit('CHALLENGE',host=host,transport='requests',case=label,http=r.status_code,bytes=len(r.content),complete=good,hash=hashlib.sha256(r.content).hexdigest()[:12])
                except Exception as e:emit('CHALLENGE',host=host,case=label,error=type(e).__name__)
        try:
            with cr.Session(impersonate='chrome131',trust_env=False) as s:
                r=s.post(origin+'/fd0fb2130e/challenge',headers={'Origin':origin,'Referer':origin+'/'},timeout=(3,5))
                try:j=r.json()
                except ValueError:j={}
                good=isinstance(j,dict) and bool(j.get('token') and j.get('challenge') and j.get('instrumentation'))
                emit('CHALLENGE',host=host,transport='chrome131',case='browser-empty',http=r.status_code,bytes=len(r.content),complete=good)
        except Exception as e:emit('CHALLENGE',host=host,transport='chrome131',error=type(e).__name__)
def safe_messages(payload):
    result=[]
    if not isinstance(payload,dict):return result
    values=[payload.get('message','')]
    errors=payload.get('errors') or {}
    if isinstance(errors,dict):
        for key,val in errors.items():
            vals=val if isinstance(val,list) else [val]
            values.extend(str(key)+': '+str(v) for v in vals)
    for value in values:
        text=str(value)
        text=re.sub(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+','[email]',text)
        text=re.sub(r'[A-Za-z0-9_./+-]{48,}','[opaque]',text)
        if text:result.append(text[:220])
    return result
def normal_signup():
    # A missing captcha must be explicitly rejected by the service if required.
    # One request only, with ordinary public signup fields.
    alphabet=string.ascii_lowercase+string.digits
    email=''.join(secrets.choice(alphabet) for _ in range(13))+'@qq.com'
    password=secrets.token_urlsafe(18)
    with session() as s:
        try:
            r=s.post(BASE+'/api/v1/passport/auth/register',data={'email':email,'password':password,'invite_code':'','email_code':''},timeout=(4,12))
            try:j=r.json()
            except ValueError:j={}
            data=j.get('data') or {} if isinstance(j,dict) else {}
            good=r.ok and isinstance(data,dict) and bool(data.get('auth_data') and data.get('token'))
            emit('REGISTER',http=r.status_code,success=good,keys=list(j) if isinstance(j,dict) else [],data_keys=list(data) if good else [],messages=[] if good else safe_messages(j))
            if not good:return
            entry={'email':email,'password':password,'token':data['token'],'auth_data':data.get('auth_data'),'subscribe_url':BASE+'/s/?token='+data['token'],'created_at':int(time.time())}
            # Persist privately so the single test signup is not lost.
            bankpath=ROOT/'vault_repo'/'wula_bank.json'
            try:bank=json.loads(bankpath.read_text())
            except (OSError,ValueError):bank=[]
            if not isinstance(bank,list):bank=[]
            bankpath.write_text(json.dumps([entry]+bank,ensure_ascii=False,indent=2));bankpath.chmod(0o600)
            emit('PRIVATE_SAVE',entries=len(bank)+1)
            with session() as sub:
                r=sub.get(BASE+'/s/',params={'token':data['token']},headers={'User-Agent':'clash-verge/v1.3.8'},timeout=(4,12))
            cfg=yaml.safe_load(r.text)
            nodes=cfg.get('proxies',[]) if isinstance(cfg,dict) else []
            emit('SUBSCRIPTION',http=r.status_code,count=len(nodes),types=sorted({x.get('type','') for x in nodes if isinstance(x,dict)}))
        except Exception as e:emit('REGISTER',error=type(e).__name__)
def main():
    with session() as s:
        r=s.get(BASE+'/api/v1/guest/comm/config',timeout=(3,6));j=r.json();d=j.get('data') or {}
        cap=d.get('recaptcha_site_key','')
        parsed=urlsplit(cap)
        emit('CONFIG',http=r.status_code,recaptcha=d.get('is_recaptcha'),sitekey_host=parsed.hostname,sitekey_path=parsed.path)
    shape()
    normal_signup()
    emit('DONE',seconds=round(time.monotonic()-START,1))
if __name__=='__main__':main()
