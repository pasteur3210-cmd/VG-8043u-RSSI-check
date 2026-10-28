"""VG-8043u Telnet RSSI acquisition core; standard library only."""
import csv
import json
import re
import socket
import time
from datetime import datetime
from pathlib import Path

VERSION = '1.0.0'
# Report explicit RSSI and parenthesized multi-chain readings preceding FA/CCA.
EXPLICIT = re.compile(r'\bRSSI\s*[:= ]\s*\(?\s*(-?\d{1,3})\b', re.I)
CHAINS = re.compile(r'\(\s*((?:-?\d{1,3}\s+){1,15}-?\d{1,3})\s*\)\s*\(\s*(?:FA|CCA)\b', re.I)
PROMPT = re.compile(r'(?m)(?:^|\n)\s*[^\r\n]{0,65}[>#]\s*$')


def extract_rssi(raw):
    """Return candidates in acquisition order. Ignore command echoes, generic numbers."""
    results = []
    for line in raw.replace('\r', '\n').splitlines():
        if 'rssi' not in line.lower() and '(FA' not in line.upper():
            continue
        chains = CHAINS.search(line)
        if chains:
            nums = [int(x) for x in chains.group(1).split()]
            results.append({'kind': 'chains', 'values': nums, 'line': line[:700]})
        for m in EXPLICIT.finditer(line):
            results.append({'kind': 'explicit', 'values': [int(m.group(1))], 'line': line[:700]})
    return results


def judge(samples, limit=50):
    if not samples:
        return 'REVIEW', None, '未擷取到可辨識 RSSI 資料'
    values = [v for s in samples for v in s['values']]
    if not values or any(abs(x) > 127 for x in values):
        return 'REVIEW', None, '包含不合理數值，需人工確認格式'
    lo = min(values)
    return ('PASS' if lo >= limit else 'FAIL'), lo, ('全部讀值達標' if lo >= limit else '至少一筆低於門檻')


class Telnet:
    def __init__(self, host, port=23, timeout=8):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(0.25)
        self.raw = bytearray()
        self._state = 0
        self._verb = 0

    def _filter_telnet(self, data):
        out = bytearray()
        for x in data:
            if self._state == 0:
                if x == 255: self._state = 1
                else: out.append(x)
            elif self._state == 1:
                if x == 255: out.append(255); self._state = 0
                elif x in (251, 252, 253, 254): self._verb = x; self._state = 2
                elif x == 250: self._state = 3
                else: self._state = 0
            elif self._state == 2:
                # Reject optional Telnet options; avoid protocol negotiation stalls.
                reply = 254 if self._verb in (253, 254) else 252
                self.sock.sendall(bytes([255, reply, x]))
                self._state = 0
            elif self._state == 3:
                if x == 255: self._state = 4
            elif self._state == 4:
                self._state = 0 if x == 240 else 3
        return bytes(out)

    def read(self, seconds=2, until=None):
        end = time.monotonic() + seconds
        out = bytearray()
        last = time.monotonic()
        while time.monotonic() < end:
            try:
                packet = self.sock.recv(8192)
                if not packet: break
                decoded = self._filter_telnet(packet)
                out.extend(decoded)
                self.raw.extend(decoded)
                last = time.monotonic()
                if until and until(out.decode('latin1', 'replace')): break
            except socket.timeout:
                if until is None and time.monotonic() - last > 0.8: break
        return out.decode('latin1', 'replace')

    def send(self, s):
        self.sock.sendall(s.encode('ascii') + b'\r\n')

    def close(self):
        self.sock.close()


def run_test(host, user, password, serial, operator, threshold=50, duration=6, output_dir='records', port=23, log=None):
    if not serial.strip(): raise ValueError('請輸入 SN / DUT ID')
    if not 1 <= int(threshold) <= 127: raise ValueError('門檻必須介於 1~127')
    dest = Path(output_dir); dest.mkdir(parents=True, exist_ok=True)
    now = datetime.now().astimezone()
    key = re.sub(r'[^a-zA-Z0-9_-]', '_', serial)[:60]
    base = dest / (now.strftime('%Y%m%d_%H%M%S_%f') + '_' + key)
    transcript = ''
    err = ''
    events = []
    conn = None
    def step(msg):
        events.append(f'{datetime.now().astimezone().isoformat(timespec="seconds")} {msg}')
        if log: log(msg)
    try:
        step(f'Connect {host}:{port}')
        conn = Telnet(host, int(port))
        initial = conn.read(8, lambda s: re.search(r'(?:login|username)\s*:', s, re.I) is not None)
        if not re.search(r'(?:login|username)\s*:', initial, re.I):
            raise RuntimeError('未收到 Login/Username 提示')
        conn.send(user)
        prompt = conn.read(8, lambda s: re.search(r'password\s*:', s, re.I) is not None)
        if not re.search(r'password\s*:', prompt, re.I):
            raise RuntimeError('未收到 Password 提示')
        conn.send(password)
        ready = conn.read(8, lambda s: bool(PROMPT.search(s)) or 'incorrect' in s.lower() or 'failed' in s.lower())
        if not PROMPT.search(ready) or re.search(r'login incorrect|authentication failed|login failed', ready, re.I):
            raise RuntimeError('登入失敗或未取得命令提示符')
        step('Login OK')
        # Exactly follow provided command order. First command may enter debug mode.
        for cmd in ('version --debug x4Wnhq2ReL', 'sh'):
            step(f'Send {cmd.split()[0]}')
            conn.send(cmd)
            response = conn.read(4, lambda s: bool(PROMPT.search(s)))
            if not PROMPT.search(response):
                raise RuntimeError(f'{cmd.split()[0]} 後未取得命令提示符')
        step('Send rssimlo 2')
        conn.send('rssimlo 2')
        conn.read(3)
        step('Capture kernel messages (bounded)')
        conn.send('cat /proc/kmsg')
        # /proc/kmsg may be streaming or blocking. Bound capture and interrupt.
        start = time.monotonic()
        while time.monotonic() - start < float(duration):
            conn.read(0.6)
        conn.sock.sendall(b'\x03')  # Ctrl-C
        conn.read(1.5)
        transcript = conn.raw.decode('latin1', 'replace')
    except (OSError, RuntimeError, ValueError) as e:
        err = str(e); step('ERROR ' + err)
        if conn: transcript = conn.raw.decode('latin1', 'replace')
    finally:
        if conn: conn.close()
    # Keep the password out of saved logs even if remote echoes credentials.
    for secret in (password, 'x4Wnhq2ReL'):
        if secret: transcript = transcript.replace(secret, '[REDACTED]')
    # Only parse RSSI data after command, if command echoes available.
    anchor = transcript.lower().rfind('rssimlo 2')
    relevant = transcript[anchor:] if anchor != -1 else transcript
    samples = extract_rssi(relevant)
    status, minimum, reason = judge(samples, int(threshold))
    if err: status, reason = 'ERROR', err
    elif not samples: status = 'REVIEW'
    summary = dict(timestamp=now.isoformat(timespec='seconds'), model='VG-8043u', sn=serial, operator=operator,
                   host=host, port=int(port), threshold=int(threshold), capture_seconds=float(duration),
                   result=status, min_rssi=minimum, reason=reason, samples=samples, events=events,
                   raw_log=base.name + '.log')
    (base.with_suffix('.log')).write_text(transcript + '\n\n' + '\n'.join(events), encoding='utf-8')
    (base.with_suffix('.json')).write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    ledger = dest / 'RSSI_Test_Results.csv'
    new = not ledger.exists()
    with ledger.open('a', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        if new: writer.writerow(['Time','Model','SN','Operator','IP','RSSI Min','Threshold','Result','Reason','Raw Log','JSON'])
        writer.writerow([summary['timestamp'],summary['model'],serial,operator,host,minimum,threshold,status,reason,base.name+'.log',base.name+'.json'])
    return summary, base
