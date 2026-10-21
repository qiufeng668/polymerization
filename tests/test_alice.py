import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'plugins'))
import alice

NODES_YAML = """
proxies:
  - {name: HK-01, type: hysteria2, server: a.example.com, port: 443, password: 'pwd&123', sni: a.utility.com}
  - {name: US-02, type: anytls, server: b.example.com, port: 8443, password: secret2}
  - {name: LOCAL, type: ss, server: 127.0.0.1, port: 1080, password: x}
  - {name: UNKNOWN, server: c.example.com, port: 80, password: y}
"""
ENTRY = {'email': 'fixture@example.com', 'password': 'fixture-pw',
         'sub_link': 'https://sub.harnesscom.com/sub/fixturetoken', 'ts': 0}


class AliceTests(unittest.TestCase):
    def test_encoded_credentials_and_invalid_node_filter(self):
        uris, error = alice._parse_nodes(NODES_YAML)
        self.assertIsNone(error)
        self.assertEqual(len(uris), 2)
        self.assertEqual(unquote(urlsplit(uris[0]).username), 'pwd&123')
        self.assertEqual(parse_qs(urlsplit(uris[0]).query)['insecure'], ['0'])

    def test_bad_or_empty_yaml(self):
        for payload in ('', 'proxies: [broken', 'kind: nope', 'proxies: wrong'):
            nodes, error = alice._parse_nodes(payload)
            self.assertEqual(nodes, [])
            self.assertTrue(error)

    def test_vless_reality_fields_survive(self):
        uri = alice._to_uri({'name': 'Reality', 'type': 'vless', 'server': '::1', 'port': 443,
                             'uuid': 'fixture-id', 'tls': True, 'flow': 'xtls-rprx-vision',
                             'reality-opts': {'public-key': 'fixture-key', 'short-id': 'aabb'}})
        parsed = urlsplit(uri)
        self.assertEqual(parsed.hostname, '::1')
        query = parse_qs(parsed.query)
        self.assertEqual(query['sid'], ['aabb'])
        self.assertEqual(query['flow'], ['xtls-rprx-vision'])
        self.assertEqual(query['pbk'], ['fixture-key'])

    def test_download_uses_one_link_and_real_text_fixture(self):
        session = MagicMock()
        session.__enter__.return_value = session
        response = session.get.return_value
        response.text = NODES_YAML
        with patch.object(alice, '_new_session', return_value=session):
            uris, error = alice.fetch_nodes(ENTRY['sub_link'])
        self.assertIsNone(error)
        self.assertEqual(len(uris), 2)
        self.assertEqual(session.get.call_count, 1)
        self.assertEqual(session.get.call_args.args[0], ENTRY['sub_link'] + '/clash_meta')

    def test_cached_account_writes_plain_txt_without_register(self):
        uris, _ = alice._parse_nodes(NODES_YAML)
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(alice, '_load_bank', return_value=[dict(ENTRY)]), \
             patch.object(alice, '_save_bank') as save, \
             patch.object(alice, 'fetch_nodes', return_value=(uris, None)), \
             patch.object(alice, 'register') as register:
            self.assertEqual(alice.main(['--outdir', tmp]), 0)
            self.assertEqual((Path(tmp) / 'nodes.txt').read_text().splitlines(), uris)
            register.assert_not_called()
            self.assertEqual(len(save.call_args.args[0]), 1)

    def test_failure_does_not_report_old_output_as_success(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(alice, '_load_bank', return_value=[dict(ENTRY)]), \
             patch.object(alice, 'fetch_nodes', return_value=([], 'fixture failure')), \
             patch.object(alice, 'register') as register:
            output = Path(tmp) / 'nodes.txt'
            output.write_text('hy2://stale@old.example:443#old\n')
            self.assertEqual(alice.main(['--outdir', tmp]), 2)
            self.assertEqual(output.read_text(), '')
            register.assert_not_called()

    def test_retry_never_creates_a_second_identity(self):
        context = MagicMock()
        with patch.object(alice, '_new_session', return_value=context), \
             patch.object(alice, '_claim_link', side_effect=[RuntimeError('network'), ENTRY['sub_link']]) as claim, \
             patch.object(alice.time, 'sleep'):
            account = alice.register()
        self.assertEqual(claim.call_count, 2)
        self.assertEqual(claim.call_args_list[0].args[1:], claim.call_args_list[1].args[1:])
        self.assertEqual(account['sub_link'], ENTRY['sub_link'])


if __name__ == '__main__':
    unittest.main()
