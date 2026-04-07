# forensics/hash_chain.py

import hashlib
import json


class HashChain:
    """
    Maintains a SHA-256 hash chain for log integrity.
    """

    def __init__(self):
        self.previous_hash = "0" * 64  # Genesis hash

    def compute_hash(self, event: dict) -> str:
        """
        Compute SHA-256 hash of event + previous hash.
        """
        data = json.dumps(event, sort_keys=True)
        combined = data + self.previous_hash
        digest = hashlib.sha256(combined.encode()).hexdigest()
        self.previous_hash = digest
        return digest
