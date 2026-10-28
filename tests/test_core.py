import unittest
from rssi_core import extract_rssi, judge
class RSSITests(unittest.TestCase):
    def test_pass(self):
        s=extract_rssi('<4>[Rssi 89](rty 0%)(90 92 86 88 86)(FA 28)(CCA 196)')
        self.assertEqual(judge(s)[0], 'PASS')
        self.assertEqual(judge(s)[1], 86)
    def test_fail(self):
        self.assertEqual(judge(extract_rssi('(88 49 87 88 84)(FA 35)(CCA 129)'))[0], 'FAIL')
    def test_no_data(self):
        self.assertEqual(judge(extract_rssi('something 90 80 70'))[0], 'REVIEW')
    def test_threshold_edge(self):
        self.assertEqual(judge(extract_rssi('Rssi 50'))[0], 'PASS')
    def test_negative(self):
        self.assertEqual(judge(extract_rssi('RSSI -60'))[0], 'FAIL')
if __name__=='__main__': unittest.main()
