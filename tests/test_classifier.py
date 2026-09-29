import unittest
from ml.classifier import ThreatClassifier
from scripts.generate_demo_data import create_synthetic_flow

class TestThreatClassifier(unittest.TestCase):
    def setUp(self):
        self.classifier = ThreatClassifier()
        self.classifier.load()

    def test_predict_single_syn_flood(self):
        flow = create_synthetic_flow("SYN_FLOOD", 0.0)
        threat, conf, probs = self.classifier.predict_single(flow)
        self.assertEqual(threat, "SYN_FLOOD")
        self.assertGreater(conf, 0.5)

    def test_predict_single_dns_tunnel(self):
        flow = create_synthetic_flow("DNS_TUNNEL", 0.0)
        threat, conf, probs = self.classifier.predict_single(flow)
        self.assertEqual(threat, "DNS_TUNNEL")
        self.assertGreater(conf, 0.5)

if __name__ == "__main__":
    unittest.main()
