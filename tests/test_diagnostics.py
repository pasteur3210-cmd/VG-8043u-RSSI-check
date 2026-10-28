import socket
import tempfile
import unittest
from pathlib import Path
from rssi_core import run_test, VERSION

class DiagnosticsTests(unittest.TestCase):
    def test_refused_connection_produces_all_records(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        with tempfile.TemporaryDirectory() as folder:
            summary, base = run_test('127.0.0.1','root','secret123','UNIT-SN','QA', 50, .1, folder, port)
            self.assertEqual(summary['result'], 'ERROR')
            self.assertEqual(summary['failure_phase'], 'TCP_CONNECT')
            for suffix in ('.log','.debug.log','.execution.log','.test.log','.json'):
                self.assertTrue(Path(str(base)+suffix).exists(),suffix)
            debug=Path(str(base)+'.debug.log').read_text(encoding='utf-8')
            self.assertIn('TCP_CONNECT_FAIL',debug)
            self.assertNotIn('secret123',debug)
            self.assertEqual(summary['version'],VERSION)
