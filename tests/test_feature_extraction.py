import unittest
from ml.feature_extraction import (
    calculate_shannon_entropy, calculate_dns_tunnel_score,
    calculate_dga_score, calculate_beacon_score, extract_features_from_dict
)

class TestFeatureExtraction(unittest.TestCase):
    def test_shannon_entropy(self):
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        self.assertGreater(calculate_shannon_entropy("a8f9b2c3d4e5f6"), 3.0)

    def test_dns_tunnel_score(self):
        score = calculate_dns_tunnel_score(domain_length=60, entropy=4.8, subdomain_depth=4, query_freq=150)
        self.assertGreater(score, 70.0)

    def test_dga_score(self):
        res = calculate_dga_score("x9k3p7m2q1z.biz", entropy=4.2)
        self.assertIn("dga_score", res)
        self.assertGreater(res["dga_score"], 50.0)

    def test_extract_features_from_dict(self):
        flow = {
            "flow_duration": 2.5,
            "packets": 100,
            "bytes": 50000,
            "syn_count": 5,
            "ack_count": 95,
            "domain_name": "ntro.gov.in"
        }
        feats = extract_features_from_dict(flow)
        self.assertEqual(feats["packets"], 100)
        self.assertEqual(feats["bytes"], 50000)
        self.assertIn("ack_syn_ratio", feats)

if __name__ == "__main__":
    unittest.main()
