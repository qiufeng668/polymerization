import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('atvpn_plugin',ROOT/'plugins/atvpn.py')
atvpn=importlib.util.module_from_spec(spec);spec.loader.exec_module(atvpn)

class AtvpnPluginTests(unittest.TestCase):
    def test_interval_is_twelve_hours(self):
        line=(ROOT/'plugins/atvpn.py').read_text().splitlines()[2]
        self.assertIn('@interval: 12h',line)
    def test_output_is_single_subscription_and_plain_nodes(self):
        with tempfile.TemporaryDirectory() as tmp:
            sub,nodes=atvpn._write_outputs(tmp,'https://atvpn.cc/s/fixture',[
                'vless://a@example:443#A','vless://a@example:443#A','hy2://b@example:443#B'])
            self.assertEqual(Path(sub).read_text().splitlines(),['https://atvpn.cc/s/fixture'])
            self.assertEqual(Path(nodes).read_text().splitlines(),['vless://a@example:443#A','hy2://b@example:443#B'])
    def test_failed_refresh_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            atvpn._write_outputs(tmp,'https://atvpn.cc/s/old',['hy2://old@example:443#old'])
            with patch.object(atvpn,'do_one',return_value=None),patch('sys.argv',['atvpn.py','--outdir',tmp]),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(atvpn.main(),2)
            self.assertEqual((Path(tmp)/'subscription.txt').read_text().strip(),'https://atvpn.cc/s/old')
            self.assertEqual((Path(tmp)/'nodes.txt').read_text().strip(),'hy2://old@example:443#old')
    def test_clash_yaml_and_base64_are_converted(self):
        yaml_text='proxies:\n  - {name: h, type: hysteria2, server: h.example, port: 443, password: p}\n'
        self.assertTrue(atvpn.decode_subscription(yaml_text)[0].startswith('hy2://'))
if __name__=='__main__':unittest.main()
