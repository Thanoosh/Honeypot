# behaviour/feature_extractor.py

from collections import defaultdict
import time


class FeatureExtractor:
    """
    Extracts behavioural features per attacker session (IP-based for now).
    """

    def __init__(self):
        self.sessions = defaultdict(list)

    def record_event(self, event: dict):
        ip = event["details"].get("client_ip", "unknown")
        timestamp = time.time()

        self.sessions[ip].append(timestamp)

        return self.extract_features(ip)

    def extract_features(self, ip: str) -> dict:
        timestamps = self.sessions[ip]

        count = len(timestamps)

        if count < 2:
            avg_interval = None
        else:
            intervals = [
                timestamps[i] - timestamps[i - 1]
                for i in range(1, count)
            ]
            avg_interval = sum(intervals) / len(intervals)

        return {
            "attack_count": count,
            "avg_interval": avg_interval
        }
