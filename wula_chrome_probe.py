"""Real stock Chrome in GitHub runner. Network diagnostics only, no signup/proof."""
import hashlib,json,re,shutil,time
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright
START=time.monotonic()
def emit(kind,**kw):print('CHROME_'+kind,json.dumps(kw,ensure_ascii=False),flush=True)
def safe_error(exc):
    text=str(exc).split('\n')[0][:260]
    return re.sub(r'(token|password|auth_data)=[^&\s]+',r'\1=[hidden]',text)
def main():
    path=next((shutil.which(name) for name in ('google-chrome','google-chrome-stable','chromium','chromium-browser') if shutil.which(name)),None)
    emit('BINARY',present=bool(path))
    if not path:raise RuntimeError('Runner stock Chrome missing')
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=path,headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
        emit('VERSION',version=browser.version)
        context=browser.new_context()
        page=context.new_page()
        for host in ('main.wulavpn.com','wula001.com','wulass.org'):
            origin='https://'+host
            try:
                r=page.goto(origin+'/',wait_until='domcontentloaded',timeout=12000)
                emit('ROOT',host=host,http=r.status if r else None,final_host=urlsplit(page.url).hostname)
            except Exception as e:emit('ROOT',host=host,error=safe_error(e));continue
            for path in ('/api/v1/guest/comm/config','/fd0fb2130e/challenge'):
                try:
                    result=page.evaluate('''async ({path})=>{
                      try {
                        const r=await fetch(path,{method:path.endsWith('challenge')?'POST':'GET',signal:AbortSignal.timeout(8000)});
                        const text=await r.text();let j={};try{j=JSON.parse(text)}catch{}
                        return {http:r.status,type:r.headers.get('content-type'),bytes:text.length,keys:Object.keys(j),complete:Boolean(j.token&&j.challenge&&j.instrumentation)};
                      } catch(e) {return {error:e.name}};
                    }''',{'path':path})
                    emit('FETCH',host=host,path=path,**result)
                except Exception as e:emit('FETCH',host=host,path=path,error=safe_error(e))
        browser.close()
    emit('DONE',seconds=round(time.monotonic()-START,1))
if __name__=='__main__':main()
