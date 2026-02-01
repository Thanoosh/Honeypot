# forensics/logger.py

import json
import hashlib
import datetime
import os


class CentralLogger:
    def __init__(self, log_dir="data/logs"):
        os.makedirs(log_dir, exist_ok=True)
        self.log_file = os.path.join(log_dir, "events.log")

    def log_event(self, event: dict):
        event_copy = dict(event)

        # Hash for integrity
        event_copy["hash"] = hashlib.sha256(
            json.dumps(event, sort_keys=True).encode()
        ).hexdigest()

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_copy) + "\n")

    # 🔑 compatibility alias (THIS FIXES YOUR ERROR)
    def log(self, event: dict):
        self.log_event(event)
