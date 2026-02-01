# ml/feature_extractor.py

import numpy as np
import math
import time

def shannon_entropy(text: str):
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return entropy

class FeatureExtractor:
    def extract(self, text, last_time=None):
        now = time.time()
        delta = now - last_time if last_time else 0.0

        return {
            "length": len(text),
            "entropy": shannon_entropy(text),
            "interval": delta,
            "timestamp": now
        }
