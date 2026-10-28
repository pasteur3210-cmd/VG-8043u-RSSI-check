import socket
import threading
import tempfile
import unittest
from pathlib import Path
from rssi_core import run_test


def fake_device(mode, listener, seen):
    c, _ = listener.accept()
    c.settimeout(5)
    try:
        c.sendall(bytes([255, 251, 1, 255, 253, 3]))  # WILL ECHO, DO SGA
        if mode == 'prompt':
            c.sendall(b'login: ')
        else:
            # Wait for wake-up CRLF, skipping Telnet IAC responses.
            data = b''
            while b'\n' not in data:
                data += c.recv(1024)
            c.sendall(b'login: ')
        def line():
            b = b''
            while not b.endswith(b'\n'):
                t = c.recv(1024)
                if not t: return b''
                b += t
            return b.decode('latin1').strip().replace('ÿü\x01ÿþ\x03','').replace('ÿý\x01ÿû\x03','')
        seen.append(line())
        c.sendall(b'Password: ')
        seen.append(line())
        c.sendall(b'\r\n> ')
        seen.append(line())
        c.sendall(b'Serial Number: TEST123\r\n> ')
        seen.append(line())
        c.sendall(b'\r\n> ')
        c.sendall(b'\r\n# ')
        seen.append(line())
        c.sendall(b'[Rssi 89](rty 0%)(90 92 86 88 86)(FA 28)(CCA 196)\n# ')
        seen.append(line())
        c.sendall(b'[Rssi 89](rty 0%)(90 92 86 88 86)(FA 28)(CCA 196)\n')
        while True:
            if not c.recv(1024): break
    except (socket.timeout, OSError):
        pass
    finally:
        c.close()
        listener.close()

class TelnetTests(unittest.TestCase):
    def check_mode(self, mode):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
        port=listener.getsockname()[1]
        seen=[]
        t=threading.Thread(target=fake_device,args=(mode,listener,seen),daemon=True);t.start()
        with tempfile.TemporaryDirectory() as tmp:
            result, base=run_test('127.0.0.1','root','12345','TEST123','QA',50,0.1,tmp,port)
            log=Path(str(base)+'.log').read_text(encoding='utf-8')
            self.assertEqual(result['result'],'PASS',result)
            self.assertIn('Initial RX',log)
            self.assertNotIn('12345',log)
            self.assertNotIn('x4Wnhq2ReL',log)
            self.assertEqual(seen[:2], ['root','12345'])
        t.join(2)
    def test_immediate_login(self): self.check_mode('prompt')
    def test_login_after_enter(self): self.check_mode('wake')

if __name__=='__main__': unittest.main()
