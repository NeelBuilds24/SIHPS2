import unittest
from ml.anomaly_detector import AnomalyDetector

class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AnomalyDetector()
        self.detector.load()

    def test_anomaly_detection_normal(self):
        flow = {
            "flow_duration": 2.0,
            "packets": 20,
            "bytes": 1200,
            "syn_count": 1,
            "ack_count": 18,
            "protocol": "TCP"
        }
        score, status, is_anom = self.detector.predict_single(flow)
        self.assertLessEqual(score, 0.6)

    def test_anomaly_detection_extreme(self):
        flow = {
            "flow_duration": 0.5,
            "packets": 50000,
            "bytes": 50000000,
            "syn_count": 50000,
            "ack_count": 0,
            "protocol": "TCP"
        }
        score, status, is_anom = self.detector.predict_single(flow)
        self.assertTrue(is_anom)
        self.assertIn(status, ["ANOMALOUS", "HIGHLY ANOMALOUS"])

if __name__ == "__main__":
    unittest.main()
