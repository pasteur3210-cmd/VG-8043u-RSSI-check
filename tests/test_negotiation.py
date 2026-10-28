import socket
import threading
import tempfile
import unittest
from pathlib import Path
from rssi_core import run_test

class NegotiationTests(unittest.TestCase):
    def test_silent_until_terminal_type(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        port=listener.getsockname()[1]
        def server():
            conn,_=listener.accept();conn.settimeout(12)
            try:
                payload=b''
                while b'\xff\xfb\x18' not in payload:
                    payload += conn.recv(1024)
                conn.sendall(b'login: ')
                remaining = b''
                def line():
                    nonlocal remaining
                    while b'\n' not in remaining:
                        remaining+=conn.recv(1024)
                    part,remaining=remaining.split(b'\n',1)
                    return part.strip(b'\r')
                # Extra Telnet IAC sequences may precede username.
                self.assertTrue(line().endswith(b'root'))
                conn.sendall(b'Password: ')
                self.assertEqual(line(),b'12345')
                conn.sendall(b'> ')
                self.assertEqual(line(),b'serialnumber')
                conn.sendall(b'Serial Number: TEST123\r\n> ')
                self.assertTrue(line().startswith(b'version'))
                conn.sendall(b'> ')
                self.assertEqual(line(),b'sh')
                conn.sendall(b'# ')
                self.assertEqual(line(),b'rssimlo 2')
                conn.sendall(b'[Rssi 89](rty 0%)(90 92 86 88 86)(FA 28)(CCA 196)\r\n# ')
                self.assertEqual(line(),b'cat /proc/kmsg')
                conn.sendall(b'[Rssi 89](rty 0%)(90 92 86 88 86)(FA 28)(CCA 196)\r\n')
                conn.recv(1024)
            finally:conn.close();listener.close()
        thread=threading.Thread(target=server,daemon=True);thread.start()
        with tempfile.TemporaryDirectory() as d:
            result,base=run_test('127.0.0.1','root','12345','TEST123','QA',50,0.1,d,port)
            self.assertEqual(result['result'],'PASS',result)
            evidence=Path(str(base)+'.log').read_text(encoding='utf8')
            self.assertIn('TX IAC 251 24',evidence)
            self.assertNotIn('12345',evidence)
        thread.join(3)
