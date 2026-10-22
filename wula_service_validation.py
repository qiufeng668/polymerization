"""Validate the split-services candidate on runner without creating any account.
The private vault is read only remotely; local cache timestamps may be updated.
"""
import importlib.util,json,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('wula_service_candidate',ROOT/'plugins/wula.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
def emit(kind,**kw):print('SERVICE_'+kind,json.dumps(kw,ensure_ascii=False),flush=True)
def main():
    w._DEADLINE=time.monotonic()+60;w.PROXY=None
    hit=w._use_bank()
    assert hit and hit[1],'Existing cached-account subscription path regressed'
    emit('REUSE',success=True,nodes=len(hit[1]),panel=w.PANEL_BASE,subscribe=w.SUBSCRIBE_BASE)
    # Only challenge retrieval. No redemption, signup request, or external account write.
    with w._new_session() as session:
        session.headers.update({'User-Agent':w._UAS[0],'Origin':w.PANEL_BASE,'Referer':w.PANEL_BASE+'/'})
        try:
            challenge,endpoint=w._get_challenge(session)
            emit('CHALLENGE',available=True,endpoint=endpoint,complete=bool(challenge.get('instrumentation')))
        except w._CaptchaUnavailable as error:
            emit('CHALLENGE',available=False,stages=[{'stage':e.stage,'kind':e.kind,'http':e.status} for e in error.failures],fingerprint_submitted=False,retry_route=error.retry_route)
    emit('DONE',existing_subscription_passed=True,registration_attempted=False)
if __name__=='__main__':main()
