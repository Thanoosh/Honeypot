# behaviour/feature_extractor.py

import math
import time
from collections import defaultdict
from typing import Dict, Any


class FeatureExtractor:
    """
    Extracts behavioural features from attacker events.
    Stateless per call, stateful per attacker handled in classifier.
    """

    def __init__(self):
        self.last_seen = defaultdict(float)
        self.event_count = defaultdict(int)

    def extract(self, ip: str, event: Dict[str, Any]) -> Dict[str, Any]:
        payload = str(event.get("details", {}).get("payload", ""))

        now = time.time()
        last = self.last_seen[ip]

        interval = now - last if last else 0
        self.last_seen[ip] = now

        self.event_count[ip] += 1

        return {
            "entropy": self._entropy(payload),
            "interval": round(interval, 3),
            "repetition": self.event_count[ip],
            "payload_length": len(payload),
        }

    def _entropy(self, data: str) -> float:
        if not data:
            return 0.0

        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)

        return round(entropy, 3)
