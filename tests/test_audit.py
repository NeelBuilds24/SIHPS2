import unittest
from blockchain.audit_chain import AuditChain

class TestAuditChain(unittest.TestCase):
    def test_audit_chain_validity(self):
        chain = AuditChain()
        chain.add_evidence("ALERT-00001", "CHAIN-00001", {"threat": "SYN_FLOOD", "risk": 85})
        chain.add_evidence("ALERT-00002", "CHAIN-00001", {"threat": "C2_BEACON", "risk": 90})

        valid, status, _ = chain.verify_chain()
        self.assertTrue(valid)
        self.assertIn("VALID", status)

    def test_tamper_simulation(self):
        chain = AuditChain()
        chain.add_evidence("ALERT-00001", "CHAIN-00001", {"threat": "SYN_FLOOD", "risk": 85})
        
        # Tamper block 1
        chain.simulate_tampering(1)
        valid, status, _ = chain.verify_chain()
        self.assertFalse(valid)
        self.assertIn("INVALID", status)

if __name__ == "__main__":
    unittest.main()
