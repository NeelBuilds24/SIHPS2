import hashlib
import json
import time
from typing import Dict, Any, List, Tuple

class AuditBlock:
    def __init__(
        self,
        index: int,
        timestamp: str,
        alert_id: str,
        attack_chain_id: str,
        evidence_data: Dict[str, Any],
        previous_hash: str
    ):
        self.index = index
        self.timestamp = timestamp
        self.alert_id = alert_id
        self.attack_chain_id = attack_chain_id
        self.evidence_data = evidence_data
        self.evidence_hash = self.calculate_evidence_hash(evidence_data)
        self.previous_hash = previous_hash
        self.hash = self.calculate_block_hash()

    @staticmethod
    def calculate_evidence_hash(evidence: Dict[str, Any]) -> str:
        serialized = json.dumps(evidence, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def calculate_block_hash(self) -> str:
        block_string = f"{self.index}{self.timestamp}{self.alert_id}{self.attack_chain_id}{self.evidence_hash}{self.previous_hash}"
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "alert_id": self.alert_id,
            "attack_chain_id": self.attack_chain_id,
            "evidence_hash": self.evidence_hash,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
            "evidence_data": self.evidence_data
        }


class AuditChain:
    """Lightweight Permissioned Hash Chain for Tamper-Evident Security Evidence Integrity."""
    def __init__(self):
        self.chain: List[AuditBlock] = []
        self.is_tampered = False
        self.tampered_block_index: int = -1
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis_block = AuditBlock(
            index=0,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            alert_id="ALERT-00000-GENESIS",
            attack_chain_id="CHAIN-00000-GENESIS",
            evidence_data={"system": "SentinelGraph Monitoring Enclave Initialized"},
            previous_hash="0" * 64
        )
        self.chain.append(genesis_block)

    def add_evidence(self, alert_id: str, attack_chain_id: str, evidence_data: Dict[str, Any]) -> AuditBlock:
        """Append new security alert evidence to the hash chain."""
        prev_block = self.chain[-1]
        new_block = AuditBlock(
            index=len(self.chain),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            alert_id=alert_id,
            attack_chain_id=attack_chain_id,
            evidence_data=evidence_data,
            previous_hash=prev_block.hash
        )
        self.chain.append(new_block)
        return new_block

    def verify_chain(self) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """
        Verify mathematical integrity of the blockchain hash links and evidence hashes.
        Returns (is_valid, status_message, list_of_verification_details).
        """
        details = []
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            # Re-calculate block hash
            calc_hash = curr.calculate_block_hash()
            calc_evidence_hash = curr.calculate_evidence_hash(curr.evidence_data)

            if curr.evidence_hash != calc_evidence_hash:
                msg = f"Evidence tampering detected at Block #{curr.index}! Evidence payload modified."
                details.append({"block_index": curr.index, "status": "INVALID_EVIDENCE_HASH"})
                return False, f"AUDIT STATUS: INVALID — {msg}", details

            if curr.hash != calc_hash:
                msg = f"Block hash mismatch at Block #{curr.index}! Block contents altered."
                details.append({"block_index": curr.index, "status": "INVALID_BLOCK_HASH"})
                return False, f"AUDIT STATUS: INVALID — {msg}", details

            if curr.previous_hash != prev.hash:
                msg = f"Chain link broken at Block #{curr.index}! Previous hash does not match."
                details.append({"block_index": curr.index, "status": "BROKEN_PREVIOUS_HASH"})
                return False, f"AUDIT STATUS: INVALID — {msg}", details

            details.append({"block_index": curr.index, "status": "VALID"})

        return True, "AUDIT STATUS: VALID — Cryptographic Hash Chain Integrity Verified", details

    def simulate_tampering(self, block_index: int = 1) -> bool:
        """Simulate malicious alteration of an alert's evidence data in history."""
        if block_index < 1 or block_index >= len(self.chain):
            if len(self.chain) > 1:
                block_index = 1
            else:
                return False

        block = self.chain[block_index]
        # Maliciously modify evidence data without re-hashing the chain
        block.evidence_data["threat"] = "BENIGN"
        block.evidence_data["risk_score"] = 0.0
        block.evidence_data["tamper_flag"] = "TAMPERED_BY_SIMULATION"
        self.is_tampered = True
        self.tampered_block_index = block_index
        return True

    def reset_tampering(self):
        """Reset the audit chain back to genesis."""
        self.chain = []
        self.is_tampered = False
        self.tampered_block_index = -1
        self._create_genesis_block()

    def to_list(self) -> List[Dict[str, Any]]:
        return [b.to_dict() for b in self.chain]
