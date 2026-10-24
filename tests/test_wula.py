"""Offline regression tests. Run: python3 -m unittest discover -s tests -v"""
import contextlib
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
w = load('wula_test_module', ROOT / 'plugins/wula.py')
scanner = load('wula_scanner_test', ROOT / 'wula_node_scanner.py')
engine = load('engine_test_module', ROOT / 'main_engine.py')
SAMPLE = {'proxies': [
    {'name': 'HY2 test', 'type': 'hysteria2', 'server': 'hy.example.com', 'port': 443, 'password': 'test-only', 'sni': 'hy.example.com'},
    {'name': 'AnyTLS test', 'type': 'anytls', 'server': 'tls.example.com', 'port': 8443, 'password': 'a@b:c', 'sni': 'tls.example.com'}]}
YAML_TEXT = yaml.safe_dump(SAMPLE)

class WulaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for p in [patch.object(w, '_DEADLINE', None), patch.object(w, 'PROXY', None),
                  patch.object(w, '_vault_dir', return_value=self.temp.name),
                  patch.object(w.time, 'sleep')]:
            p.start()
            self.addCleanup(p.stop)

    def fetch(self, text=YAML_TEXT, error=None):
        session = MagicMock()
        session.__enter__.return_value = session
        response = session.get.return_value
        response.text = text
        if error:
            response.raise_for_status.side_effect = error
        with patch.object(w, '_new_session', return_value=session):
            result = w._fetch_nodes('fixture-token')
        return result

    def test_valid_subscription(self):
        text, nodes, error = self.fetch()
        self.assertIsNone(error)
        self.assertEqual(len(nodes), 2)
        self.assertTrue(nodes[0].startswith('hy2://'))
        self.assertIn('a%40b%3Ac@', nodes[1])

    def test_html_is_error(self):
        self.assertTrue(self.fetch('<html>not YAML</html>')[2])

    def test_empty_subscription_is_error(self):
        self.assertTrue(self.fetch('proxies: []')[2])

    def test_http_error_is_error_and_redacted(self):
        error = requests.HTTPError('403 url: https://example.com/?token=fixture-secret')
        result = self.fetch(error=error)
        self.assertTrue(result[2])
        self.assertNotIn('fixture-secret', result[2])

    def test_invalid_nodes_are_rejected(self):
        self.assertTrue(self.fetch(yaml.safe_dump({'proxies': [None, {},
            {**SAMPLE['proxies'][0], 'server': '127.0.0.1'},
            {**SAMPLE['proxies'][0], 'port': 70000}]}))[2])

    def test_proxy_session_disables_environment_proxy(self):
        with patch.object(w, 'PROXY', 'http://127.0.0.1:19999'):
            with w._new_session() as s:
                self.assertFalse(s.trust_env)
                self.assertEqual(s.proxies['https'], w.PROXY)

    def test_default_network_keeps_environment_proxy(self):
        with w._new_session() as s:
            self.assertTrue(s.trust_env)

    def run_main(self, proxy_arg=None, proxy_env=None, fail=False):
        acc = {'email': 'fixture@example.com', 'password': 'fixture-password', 'token': 'fixture-token'}
        observed = []
        def register(*args):
            observed.append(w.PROXY)
            if fail:
                raise RuntimeError('fixture failure')
            return acc.copy()
        argv = ['wula.py', '--outdir', self.temp.name]
        if proxy_arg:
            argv += ['--proxy', proxy_arg]
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(w.sys, 'argv', argv))
            stack.enter_context(patch.dict(os.environ, {'WULA_MAX_ATTEMPTS': '1', 'WULA_PROXY': proxy_env or ''}))
            for name, value in [('_load_node_pool', []), ('_use_bank', None), ('_save_bank', None),
                                ('_mark_used', None), ('_stop_node_proxy', None)]:
                stack.enter_context(patch.object(w, name, return_value=value))
            stack.enter_context(patch.object(w, '_register_one', side_effect=register))
            stack.enter_context(patch.object(w, '_fetch_nodes', return_value=(YAML_TEXT, ['hy2://fixture@hy.example.com:443#fixture'], None)))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            w.main()
        return observed

    def test_cli_proxy_preserved(self):
        self.assertEqual(self.run_main(proxy_arg='http://127.0.0.1:19999'), ['http://127.0.0.1:19999'])

    def test_environment_proxy_preserved(self):
        self.assertEqual(self.run_main(proxy_env='http://127.0.0.1:19998'), ['http://127.0.0.1:19998'])

    def test_failure_exits_nonzero(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_main(fail=True)
        self.assertEqual(caught.exception.code, 2)

    def test_legacy_timeout_burn_not_trusted(self):
        with patch.object(w, '_load_burn', return_value={'192.0.2.1': {'fails': 3}}):
            self.assertFalse(w._is_burned('192.0.2.1'))

    def test_budget_stops_pow(self):
        with patch.object(w, '_DEADLINE', time.monotonic() - 1):
            with self.assertRaises(w._BudgetExceeded):
                w._solve_pow('fixture', 'ffff')

    def test_scanner_cache_version_and_deep(self):
        pool = Path(self.temp.name) / 'pool.json'
        data = {'ts': time.time(), 'nodes': {'fixture': {}}, 'deep': True}
        with patch.object(scanner, 'POOL_FILE', str(pool)):
            pool.write_text(json.dumps(data))
            self.assertFalse(scanner._pool_age_ok(3600, True)[0])
            data['schema_version'] = scanner.SCHEMA_VERSION
            pool.write_text(json.dumps(data))
            self.assertTrue(scanner._pool_age_ok(3600, True)[0])
            data['deep'] = False
            pool.write_text(json.dumps(data))
            self.assertFalse(scanner._pool_age_ok(3600, True)[0])

    def test_full_aggregate_keeps_single_source_unfiltered(self):
        raw=[]
        for i in range(4):
            raw.append('hy2://h%d@hy%d.example:443?sni=hy%d.example&insecure=1#wula HY2-%d'%(i,i,i,i))
            raw.append('hysteria2://h%d@hy%d.example:443?sni=hy%d.example&insecure=1#wula HY2-%d'%(i,i,i,i))
        for i in range(27):
            raw.append('anytls://a%d@at%d.example:443/?sni=at%d.example#wula AnyTLS-%d'%(i,i,i,i))
        plugin_reports=[{'name':'wula.py','interval':'12小时','status':'✅','count':35,'fail_count':0,'advice':'ok'}]
        with tempfile.TemporaryDirectory() as folder:
            with contextlib.ExitStack() as stack:
                patches = [
                    patch.object(engine,'VAULT_DIR',folder),
                    patch.object(engine,'PRE_TEST_FILE',str(Path(folder)/'pre.txt')),
                    patch.object(engine,'filter_dead_pairs',side_effect=lambda nodes:nodes),
                    patch.object(engine,'speedtest_modern_nodes',return_value=[raw[-1]]),
                    patch.object(engine,'export_clash_yaml',side_effect=lambda nodes,path:len(nodes)),
                    patch.object(engine,'export_egern_yaml',side_effect=lambda nodes,path:len(nodes)),
                    patch.object(engine,'export_singbox_json',side_effect=lambda nodes,path:len(nodes)),
                    patch.object(engine,'export_surge_ini',side_effect=lambda nodes,path:len(nodes)),
                    patch.object(engine,'upload_to_gist_backup',return_value=None),
                    patch.object(engine,'generate_dashboard'),
                ]
                for ctx in patches:
                    stack.enter_context(ctx)
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                engine.deduplicate_and_speedtest(raw,plugin_reports)
                aggregate=[x for x in (Path(folder)/'nodes_plain.txt').read_text().splitlines() if x.strip()]
                single=[x for x in (Path(folder)/'wula.txt').read_text().splitlines() if x.strip()]
                encoded=(Path(folder)/'wula_base64.txt').read_text()
        self.assertEqual(len(aggregate),1)
        self.assertEqual(len(single),31)
        self.assertEqual(len(base64.b64decode(encoded).decode().splitlines()),31)
        self.assertTrue(any('AnyTLS-0' in uri for uri in single))
        self.assertTrue(any('HY2-0' in uri for uri in single))
        self.assertIn('AnyTLS-26', aggregate[0])

    def test_wula_export_clears_old_files_when_source_is_empty(self):
        with tempfile.TemporaryDirectory() as folder:
            plain = Path(folder) / 'wula.txt'
            encoded = Path(folder) / 'wula_base64.txt'
            plain.write_text('hy2://stale@old.example:443#old\n')
            encoded.write_text('c3RhbGU=')
            self.assertEqual(engine.export_wula_only([], str(plain), str(encoded)), 0)
            self.assertEqual(plain.read_text(), '')
            self.assertEqual(encoded.read_text(), '')

    def test_wula_export_uses_raw_nodes_not_speed_filtered_nodes(self):
        all_nodes = [
            'anytls://secret-a@a.example:443/?sni=a.example#WuLa-A',
            'anytls://secret-b@b.example:443/?sni=b.example#WuLa-B',
            'hy2://secret-c@c.example:443?sni=c.example&insecure=1#WuLa-C',
            'hysteria2://secret-c@c.example:443?sni=c.example&insecure=1#WuLa-C',
            'vless://other@other.example:443#Other',
        ]
        final_speedtest_pass = [all_nodes[0]]
        with tempfile.TemporaryDirectory() as folder:
            plain = Path(folder) / 'wula.txt'
            encoded = Path(folder) / 'wula_base64.txt'
            count = engine.export_wula_only(all_nodes, str(plain), str(encoded))
            lines = plain.read_text().splitlines()
            self.assertEqual(count, 3)
            self.assertEqual(len(lines), 3)
            self.assertEqual(lines, all_nodes[:3])
            self.assertEqual(len(base64.b64decode(encoded.read_text()).decode().splitlines()), 3)
            self.assertEqual(final_speedtest_pass, [all_nodes[0]])

    def test_wula_export_deduplicates_repeated_endpoint_without_merging_different_nodes(self):
        nodes = [
            'hy2://secret-a@a.example:443?sni=a.example&insecure=1#wula WuLa-A',
            'hysteria2://secret-a@a.example:443?sni=a.example&insecure=1#wula WuLa-A',
            'hy2://secret-b@a.example:443?sni=a.example&insecure=1#wula WuLa-B',
            'anytls://secret-a@a.example:443/?sni=a.example#wula WuLa-AT',
            'trojan://secret-a@a.example:443?sni=a.example#Other',
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'wula.txt'
            count = engine.export_wula_only(nodes, str(path))
            self.assertEqual(count, 3)
            exported = path.read_text().splitlines()
            self.assertEqual(exported[0], nodes[0])
            self.assertIn(nodes[2], exported)
            self.assertIn(nodes[3], exported)

    def test_engine_reads_wula_protocols(self):
        nodes = ['hy2://fixture@hy.example.com:443#fixture', 'anytls://fixture@tls.example.com:8443/#fixture']
        self.assertEqual(len(engine.extract_nodes_from_text('\n'.join(nodes))), 2)

    def test_expired_bank_enters_registration_branch(self):
        entry = {'email': 'fixture@example.com', 'password': 'fixture-password', 'token': 'fixture-old'}
        fresh = {'email': 'fresh@example.com', 'password': 'fresh-password', 'token': 'fixture-new'}
        (Path(self.temp.name) / 'wula_bank.json').write_text(json.dumps([entry]))
        argv = ['wula.py', '--outdir', self.temp.name]
        def fetch(token):
            self.assertEqual(token, 'fixture-new', 'expired cached subscription must not be fetched')
            return YAML_TEXT, ['hy2://fresh@hy.example.com:443#fresh'], None
        with patch.object(w.sys, 'argv', argv), patch.dict(os.environ, {'WULA_PROXY': '', 'WULA_MAX_ATTEMPTS': '1'}), \
             patch.object(w, '_load_node_pool', return_value=[]), \
             patch.object(w, '_bank_account_usable', return_value=(False, '套餐已到期或即将到期')) as check, \
             patch.object(w, '_register_one', return_value=fresh) as register, \
             patch.object(w, '_mark_used'), patch.object(w, '_stop_node_proxy'), \
             patch.object(w, '_fetch_nodes', side_effect=fetch) as download, \
             contextlib.redirect_stdout(io.StringIO()):
            w.main()
        check.assert_called()
        register.assert_called_once()
        download.assert_called_once_with('fixture-new')
        saved = json.loads((Path(self.temp.name) / 'wula_bank.json').read_text())
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]['token'], 'fixture-new')
        self.assertIn('fresh@hy.example.com', (Path(self.temp.name) / 'nodes.txt').read_text())

    def test_expired_bank_subscription_failure_keeps_old_account(self):
        old = {'email':'old@example.com','password':'old-password','token':'old-token'}
        fresh = {'email':'fresh@example.com','password':'fresh-password','token':'new-token'}
        bank = Path(self.temp.name) / 'wula_bank.json'; bank.write_text(json.dumps([old]))
        with patch.object(w.sys,'argv',['wula.py','--outdir',self.temp.name]), \
             patch.dict(os.environ,{'WULA_PROXY':'','WULA_MAX_ATTEMPTS':'1'}), \
             patch.object(w,'_load_node_pool',return_value=[]), \
             patch.object(w,'_bank_account_usable',return_value=(False,'套餐已到期')), \
             patch.object(w,'_register_one',return_value=fresh), \
             patch.object(w,'_mark_used'),patch.object(w,'_stop_node_proxy'), \
             patch.object(w,'_fetch_nodes',return_value=(None,[],'temporary subscription failure')), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):w.main()
        self.assertEqual(json.loads(bank.read_text()),[old])

    def test_reuse_bank_does_not_register(self):
        entry = {'email': 'fixture@example.com', 'password': 'fixture-password', 'token': 'fixture-token'}
        argv = ['wula.py', '--outdir', self.temp.name]
        with patch.object(w.sys, 'argv', argv), patch.dict(os.environ, {'WULA_PROXY': ''}), \
             patch.object(w, '_load_node_pool', return_value=[]), \
             patch.object(w, '_use_bank', return_value=(entry, ['anytls://fixture@tls.example.com:443#fixture'], YAML_TEXT)), \
             patch.object(w, '_register_one') as register, contextlib.redirect_stdout(io.StringIO()):
            w.main()
            register.assert_not_called()
        self.assertTrue((Path(self.temp.name) / 'nodes.txt').read_text().strip())

    def test_modern_speedtest_missing_core_is_not_success(self):
        with patch.object(engine.shutil, 'which', return_value=None), contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(engine.speedtest_modern_nodes(['anytls://fixture@tls.example.com:443#fixture']))

    def test_modern_speedtest_uses_controller_delay(self):
        node = 'anytls://fixture@tls.example.com:443?alpn=h2%2Chttp%2F1.1#fixture'
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.return_value.ok = True
        session.get.return_value.json.return_value = {'delay': 120}
        proc = MagicMock()
        proc.poll.return_value = None
        with patch.object(engine.shutil, 'which', return_value='/fixture/mihomo'), \
             patch.object(engine.subprocess, 'Popen', return_value=proc), \
             patch.object(requests, 'Session', return_value=session), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(engine.speedtest_modern_nodes([node]), [node])
        proc.terminate.assert_called_once()
        proxy = engine.uri_to_clash_proxy(node)
        self.assertEqual(proxy['alpn'], ['h2', 'http/1.1'])

    def test_modern_speedtest_failed_delay_is_not_alive(self):
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.return_value.ok = True
        session.get.return_value.json.return_value = {'message': 'Timeout'}
        proc = MagicMock()
        proc.poll.return_value = None
        with patch.object(engine.shutil, 'which', return_value='/fixture/mihomo'), \
             patch.object(engine.subprocess, 'Popen', return_value=proc), \
             patch.object(requests, 'Session', return_value=session), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(engine.speedtest_modern_nodes(['anytls://fixture@tls.example.com:443#fixture']), [])

if __name__ == '__main__':
    unittest.main()
