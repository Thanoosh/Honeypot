# services/http/app.py

from flask import Flask, request, jsonify
import re
import requests
import time

app = Flask(__name__)

# ---------------- SERVICE MODE ----------------

SERVICE_MODE = "NORMAL"

# ---------------- SQLi DETECTION ----------------

SQLI_PATTERNS = [
    r"(?i)union\s+select",
    r"(?i)or\s+1=1",
    r"(?i)'\s*or\s*'",
    r"(?i)--",
    r"(?i)sleep\(",
]

# ---------------- CORE API ----------------

CORE_EVENT_ENDPOINT = "http://host.docker.internal:5001/event"


def detect_sqli(payload: str) -> bool:
    return any(re.search(p, payload) for p in SQLI_PATTERNS)


# ---------------- CORE COMMUNICATION ----------------

def send_event(event_type: str, details: dict) -> dict:
    """
    Sends event to core and returns full decision payload.
    """
    try:
        resp = requests.post(
            CORE_EVENT_ENDPOINT,
            json={
                "event_type": event_type,
                "details": details
            },
            timeout=5
        )
        if resp.ok:
            return resp.json()
    except Exception:
        pass

    return {}


def adapt_response(core_decision: dict):
    """
    Applies response decision from core.
    """
    global SERVICE_MODE

    if not core_decision:
        return

    response = core_decision.get("response", {})

    SERVICE_MODE = response.get("service_mode", "NORMAL")
    delay = response.get("delay", 0)

    if delay > 0:
        time.sleep(delay)


# ---------------- ROUTES ----------------

@app.route("/")
def index():
    return "<h2>Employee Portal</h2>"


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    combined = f"{username} {password}"

    # ---------- SQLi PATH ----------
    if detect_sqli(combined):
        core_decision = send_event(
            "HTTP_SQLI_ATTEMPT",
            {
                "endpoint": "/login",
                "payload": combined,
                "client_ip": request.remote_addr,
            },
        )

        adapt_response(core_decision)

        # ---------- DECEPTION ----------
        if SERVICE_MODE == "FAKE_DB":
            return jsonify(
                {
                    "status": "error",
                    "message": "SQL syntax error near 'LIMIT 1'",
                }
            ), 500

        # ---------- NORMAL ERROR ----------
        return jsonify(
            {
                "status": "error",
                "message": "Database error occurred",
            }
        ), 500

    # ---------- NORMAL LOGIN ----------
    return jsonify(
        {
            "status": "success",
            "message": "Invalid credentials",
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
