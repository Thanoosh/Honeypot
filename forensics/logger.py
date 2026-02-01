import json
import hashlib
import os

class CentralLogger:
    def __init__(self, log_dir="data/logs"):
        os.makedirs(log_dir, exist_ok=True)
        self.log_file = os.path.join(log_dir, "events.log")

    def log(self, event: dict):
        event_copy = dict(event)
        event_copy["hash"] = hashlib.sha256(
            json.dumps(event, sort_keys=True).encode()
        ).hexdigest()

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_copy) + "\n")
