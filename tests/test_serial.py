import unittest
from rssi_core import extract_serial_number, judge_serial

class SerialTests(unittest.TestCase):
    def test_sample_from_manual_session(self):
        raw = '>serialnumber\r\nSerial Number: 2634366UXXF-AN000103\r\n>'
        self.assertEqual(extract_serial_number(raw), '2634366UXXF-AN000103')
        self.assertEqual(judge_serial('2634366UXXF-AN000103', extract_serial_number(raw))[0], 'PASS')
    def test_mismatch(self):
        self.assertEqual(judge_serial('AAA', 'BBB')[0], 'FAIL')
    def test_missing(self):
        self.assertEqual(judge_serial('AAA', None)[0], 'REVIEW')
    def test_not_fooled_by_echo(self):
        self.assertIsNone(extract_serial_number('> serialnumber\r\n>'))

if __name__ == '__main__': unittest.main()
