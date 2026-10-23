"""Offline service separation/diagnostics. No network or registrations."""
import contextlib,importlib.util,io,os,tempfile,time,unittest,json
from pathlib import Path
from unittest.mock import MagicMock,patch
import requests,yaml
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('wula_endpoints_test',ROOT/'plugins/wula.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
CH={'token':'fixture-cap-token','challenge':{'c':1,'s':4,'d':1},'instrumentation':'fixture-instr'}
CONFIG={'proxies':[{'name':'fixture','type':'hysteria2','server':'public.example','port':443,'password':'fixture-secret'}]}
class Tests(unittest.TestCase):
    def setUp(self):
        for ctx in (patch.object(w,'_DEADLINE',None),patch.object(w.time,'sleep'),patch.dict(os.environ,{'WULA_CAPTCHA_BASE':''})):
            ctx.start();self.addCleanup(ctx.stop)
    def response(self,status=200,data=None,text=''):
        r=MagicMock();r.status_code=status;r.json.return_value=data;r.text=text
        return r
    def test_transport_is_not_application_rejection(self):
        s=MagicMock();s.post.side_effect=requests.ConnectTimeout('url with token=private')
        with self.assertRaises(w._EndpointError) as caught:w._json_request(s,'challenge','challenge',base='https://captcha.example/tenant')
        e=caught.exception;self.assertEqual(e.kind,'transport');self.assertNotIn('private',str(e))
    def test_http_404_separately_classified_and_closed(self):
        s=MagicMock();r=self.response(404);s.post.return_value=r
        with self.assertRaises(w._EndpointError) as caught:w._json_request(s,'challenge','challenge',base='https://captcha.example/tenant')
        self.assertEqual((caught.exception.kind,caught.exception.status),('http',404));r.close.assert_called_once()
    def test_html_200_is_not_json(self):
        s=MagicMock();r=self.response();r.json.side_effect=ValueError();s.post.return_value=r
        with self.assertRaises(w._EndpointError) as caught:w._json_request(s,'challenge','challenge')
        self.assertEqual(caught.exception.kind,'content')
    def test_budget_not_swallowed_as_transport(self):
        with patch.object(w,'_DEADLINE',time.monotonic()-1),self.assertRaises(w._BudgetExceeded):
            w._json_request(MagicMock(),'challenge','challenge')
    def test_captcha_retries_transient_tls_once_without_changing_host_or_fingerprint(self):
        session=MagicMock();session.post.side_effect=[requests.ConnectTimeout('transient'),self.response(data=CH)]
        with patch.object(w,'_DEADLINE',time.monotonic()+30),patch.object(w.time,'sleep'),contextlib.redirect_stdout(io.StringIO()):
            challenge,endpoint=w._get_challenge(session)
        self.assertEqual(challenge,CH)
        self.assertEqual(endpoint,w.CAPTCHA_BASE)
        self.assertEqual(session.post.call_count,2)
        self.assertTrue(all(call.args[0]==w.CAPTCHA_BASE+'/challenge' for call in session.post.call_args_list))
        self.assertTrue(all('json' not in call.kwargs for call in session.post.call_args_list))

    def test_captcha_retries_three_transient_transport_failures_then_succeeds(self):
        session=MagicMock();session.post.side_effect=[requests.exceptions.SSLError('one'),requests.exceptions.Timeout('two'),self.response(data=CH)]
        with patch.object(w,'_DEADLINE',time.monotonic()+30),patch.object(w.time,'sleep'),contextlib.redirect_stdout(io.StringIO()):
            challenge,endpoint=w._get_challenge(session)
        self.assertEqual(challenge,CH)
        self.assertEqual(endpoint,w.CAPTCHA_BASE)
        self.assertEqual(session.post.call_count,3)
        self.assertTrue(all(call.args[0]==w.CAPTCHA_BASE+'/challenge' for call in session.post.call_args_list))
        self.assertTrue(all('json' not in call.kwargs for call in session.post.call_args_list))

    def test_captcha_does_not_retry_http_or_content_failure(self):
        session=MagicMock();session.post.return_value=self.response(404)
        with patch.object(w,'_DEADLINE',time.monotonic()+30),patch.object(w.time,'sleep'),contextlib.redirect_stdout(io.StringIO()),self.assertRaises(w._CaptchaUnavailable):
            w._get_challenge(session)
        self.assertEqual(session.post.call_count,1)

    def test_captcha_uses_single_route_and_empty_post(self):
        # 两个验证码域名同源同 IP；首个请求失败即已封禁，回退只会加深封禁。
        s=MagicMock();s.post.return_value=self.response(data=CH)
        with contextlib.redirect_stdout(io.StringIO()):ch,endpoint=w._get_challenge(s)
        self.assertEqual(ch,CH);self.assertEqual(endpoint,w.CAPTCHA_BASE)
        self.assertEqual(s.post.call_count,1)
        self.assertNotIn('json',s.post.call_args.kwargs)
    def test_explicit_captcha_does_not_silently_change_host(self):
        s=MagicMock();s.post.return_value=self.response(404)
        with patch.dict(os.environ,{'WULA_CAPTCHA_BASE':'https://cap.example/key'}),patch.object(w,'CAPTCHA_BASE','https://cap.example/key'),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(w._CaptchaUnavailable) as caught:w._get_challenge(s)
        self.assertFalse(caught.exception.retry_route);self.assertEqual(s.post.call_count,1)
    def test_unreachable_captcha_may_change_network_not_solve(self):
        s=MagicMock();s.post.side_effect=requests.ConnectTimeout()
        with contextlib.redirect_stdout(io.StringIO()),self.assertRaises(w._CaptchaUnavailable) as caught:w._get_challenge(s)
        self.assertTrue(caught.exception.retry_route)
    def test_split_registration_fixed_identity_and_session(self):
        s=MagicMock();s.__enter__.return_value=s
        s.post.side_effect=[self.response(data=CH),self.response(data={'success':True,'token':'fixture-redeemed'}),self.response(data={'data':{'token':'fixture-sub'}})]
        with patch.object(w,'_new_session',return_value=s),patch.object(w,'_solve_challenge',return_value=[1]),patch.object(w,'_solve_instr',return_value={'fixture':True}),contextlib.redirect_stdout(io.StringIO()):
            result=w._register_one('fixture@example.com','fixture-password')
        calls=s.post.call_args_list
        self.assertEqual([c.args[0] for c in calls],[w.CAPTCHA_BASE+'/challenge',w.CAPTCHA_BASE+'/redeem',w.PANEL_BASE+'/api/v1/passport/auth/register'])
        self.assertEqual(calls[2].kwargs['data']['recaptcha_data'],'fixture-redeemed')
        self.assertEqual(result['token'],'fixture-sub');self.assertTrue(result['subscribe_url'].startswith(w.SUBSCRIBE_BASE+'/'))
    def test_unavailable_captcha_never_runs_pow_or_register(self):
        s=MagicMock();s.__enter__.return_value=s;s.post.return_value=self.response(404)
        with patch.object(w,'_new_session',return_value=s),patch.object(w,'_solve_challenge') as solve,contextlib.redirect_stdout(io.StringIO()),self.assertRaises(w._CaptchaUnavailable):
            w._register_one('fixture@example.com','fixture-password')
        solve.assert_not_called();self.assertFalse(any('/auth/register' in c.args[0] for c in s.post.call_args_list))
    def test_bad_subscription_all_routes_return_error_not_exception(self):
        s=MagicMock();s.__enter__.return_value=s;s.get.return_value.text='- scalar\n- list\n'
        with patch.object(w,'_new_session',return_value=s):text,nodes,error=w._fetch_nodes('fixture-token')
        self.assertEqual(nodes,[]);self.assertTrue(error)
    def test_subscription_empty_primary_uses_legacy(self):
        s=MagicMock();s.__enter__.return_value=s
        s.get.side_effect=[self.response(text='proxies: []'),self.response(text='proxies: []'),self.response(text=yaml.safe_dump(CONFIG))]
        with patch.object(w,'_new_session',return_value=s):text,nodes,error=w._fetch_nodes('fixture-token')
        self.assertIsNone(error);self.assertEqual(len(nodes),1)
        self.assertEqual(s.get.call_args.args[0],'https://windowsv1.com/s/')
    def test_no_duplicate_primary_subscription_request(self):
        s=MagicMock();s.__enter__.return_value=s;s.get.return_value.text=yaml.safe_dump(CONFIG)
        with patch.object(w,'_new_session',return_value=s):text,nodes,error=w._fetch_nodes('fixture-token')
        self.assertIsNone(error);self.assertEqual(s.get.call_count,1)
    def test_account_expiry_and_quota_use_panel_state(self):
        entry={'email':'fixture@example.com','password':'fixture-password','token':'fixture-token'}
        panel=MagicMock();panel.__enter__.return_value=panel
        panel.post.return_value=self.response(data={'data':{'auth_data':'fixture-auth'}})
        def verify(expiry, quota=1073741824, used=0):
            panel.get.return_value=self.response(data={'data':{'expired_at':expiry,'plan_id':1,
                                           'transfer_enable':quota,'u':used,'d':0}})
            with patch.object(w,'_new_session',return_value=panel):
                return w._bank_account_usable(entry)
        self.assertEqual(verify(time.time()-60)[0],False)
        self.assertEqual(verify(None)[0],False)
        self.assertEqual(verify(time.time()+1800)[0],False)
        self.assertEqual(verify(time.time()+7200)[0],True)
        self.assertEqual(verify(time.time()+7200,quota=10,used=10)[0],False)
        self.assertNotIn('fixture-auth',str(verify(time.time()+7200)))

    def test_expired_bank_entry_is_never_used_even_if_old_subscription_works(self):
        entry={'email':'fixture@example.com','password':'fixture-password','token':'fixture-token'}
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'wula_bank.json';path.write_text(json.dumps([entry]))
            with patch.object(w,'_vault_dir',return_value=folder), \
                 patch.object(w,'_bank_account_usable',return_value=(False,'套餐已到期或即将到期')), \
                 patch.object(w,'_fetch_nodes',return_value=(yaml.safe_dump(CONFIG),['hy2://stale@old.example:443#old'],None)) as fetch, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertIsNone(w._use_bank())
            fetch.assert_not_called()

    def test_account_email_not_printed_to_public_log(self):
        entry={'email':'fixture-private@example.com','password':'fixture-password','token':'fixture-token'}
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder)/'wula_bank.json').write_text(json.dumps([entry]))
            buf=io.StringIO()
            with patch.object(w,'_vault_dir',return_value=folder), \
                 patch.object(w,'_bank_account_usable',return_value=(False,'套餐已到期或即将到期')), \
                 contextlib.redirect_stdout(buf):
                self.assertIsNone(w._use_bank())
            self.assertNotIn('fixture-private@example.com',buf.getvalue())

    def test_unknown_panel_status_never_reuses_stale_subscription(self):
        entry={'email':'fixture@example.com','password':'fixture-password','token':'fixture-token'}
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder)/'wula_bank.json').write_text(json.dumps([entry]))
            with patch.object(w,'_vault_dir',return_value=folder), \
                 patch.object(w,'_bank_account_usable',return_value=(False,'面板暂时不可用: TimeoutError')), \
                 patch.object(w,'_fetch_nodes',return_value=(yaml.safe_dump(CONFIG),['hy2://stale@old.example:443#old'],None)) as fetch, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertIsNone(w._use_bank())
            fetch.assert_not_called()

    def test_active_bank_entry_is_validated_before_subscription(self):
        entry={'email':'fixture@example.com','password':'fixture-password','token':'fixture-token'}
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'wula_bank.json';path.write_text(json.dumps([entry]))
            with patch.object(w,'_vault_dir',return_value=folder), \
                 patch.object(w,'_bank_account_usable',return_value=(True,'账号有效')), \
                 patch.object(w,'_fetch_nodes',return_value=(yaml.safe_dump(CONFIG),['hy2://fresh@new.example:443#fresh'],None)) as fetch, \
                 contextlib.redirect_stdout(io.StringIO()):
                hit=w._use_bank()
            self.assertIsNotNone(hit);self.assertEqual(hit[1],['hy2://fresh@new.example:443#fresh'])
            fetch.assert_called_once_with('fixture-token')

    def test_endpoint_configuration_rejects_credentials_and_query(self):
        for url in ('http://a.example','https://u:p@a.example','https://a.example/?token=x'):
            with self.assertRaises(ValueError):w._https_endpoint(url,'fixture')
if __name__=='__main__':unittest.main()
