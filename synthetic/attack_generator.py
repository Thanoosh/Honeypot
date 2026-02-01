# synthetic/attack_generator.py

import time
import random
import requests


CORE_EVENT_API = "http://127.0.0.1:5001/event"

ATTACKS = [
    {
        "event_type": "HTTP_SQLI_ATTEMPT",
        "details": {
            "endpoint": "/login",
            "payload": "admin' OR 1=1 --",
            "client_ip": "10.0.0.101"
        }
    },
    {
        "event_type": "HTTP_XSS_ATTEMPT",
        "details": {
            "endpoint": "/search",
            "payload": "<script>alert(1)</script>",
            "client_ip": "10.0.0.102"
        }
    },
    {
        "event_type": "HTTP_PATH_TRAVERSAL",
        "details": {
            "endpoint": "/download",
            "payload": "../../etc/passwd",
            "client_ip": "10.0.0.103"
        }
    },
    {
        "event_type": "SSH_COMMAND",
        "details": {
            "command": "ls -la /",
            "client_ip": "10.0.0.201"
        }
    },
    {
        "event_type": "SSH_COMMAND",
        "details": {
            "command": "whoami && uname -a",
            "client_ip": "10.0.0.202"
        }
    },
    {
        "event_type": "SSH_BRUTE_FORCE",
        "details": {
            "username": "root",
            "password": "toor",
            "client_ip": "10.0.0.203"
        }
    }
]


class SyntheticAttackGenerator:
    def __init__(self, interval=5):
        self.interval = interval
        self.running = False

    def start(self):
        print("[SYNTHETIC] Attack generator started")
        self.running = True

        while self.running:
            attack = random.choice(ATTACKS)

            event = {
                **attack,
                "synthetic": True
            }

            try:
                r = requests.post(CORE_EVENT_API, json=event, timeout=2)
                if r.status_code == 200:
                    print(f"[SYNTHETIC] Sent {event['event_type']}")
                else:
                    print("[SYNTHETIC] Core rejected event")
            except Exception as e:
                print(f"[SYNTHETIC] Core unreachable: {e}")

            time.sleep(self.interval)

    def stop(self):
        self.running = False
        print("[SYNTHETIC] Attack generator stopped")


if __name__ == "__main__":
    generator = SyntheticAttackGenerator(interval=5)
    try:
        generator.start()
    except KeyboardInterrupt:
        generator.stop()
