# services/http/app.py

from flask import Flask, request, jsonify
import re
import requests
import time

app = Flask(__name__)

SQLI_PATTERNS = [
    r"(?i)union\s+select",
    r"(?i)or\s+1=1",
    r"(?i)'\s*or\s*'",
    r"(?i)--",
    r"(?i)sleep\(",
]

# 🔥 CORE API (host machine)
CORE_EVENT_ENDPOINT = "http://host.docker.internal:5001/event"


def detect_sqli(payload: str) -> bool:
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, payload):
            return True
    return False


def send_event(event_type: str, details: dict) -> str:
    try:
        response = requests.post(
            CORE_EVENT_ENDPOINT,
            json={
                "event_type": event_type,
                "details": details
            },
            timeout=5
        )
        if response.ok:
            return response.json().get("behaviour", "UNKNOWN")
    except Exception:
        pass

    return "UNKNOWN"


def adapt_response(behaviour: str):
    if behaviour == "AUTOMATED_ATTACK":
        time.sleep(2)
    elif behaviour == "PERSISTENT_ATTACKER":
        time.sleep(4)


@app.route("/")
def index():
    return "<h2>Employee Portal</h2>"


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    combined = f"{username} {password}"

    if detect_sqli(combined):
        behaviour = send_event(
            "HTTP_SQLI_ATTEMPT",
            {
                "endpoint": "/login",
                "payload": combined,
                "client_ip": request.remote_addr
            }
        )

        adapt_response(behaviour)

        return jsonify(
            {
                "status": "error",
                "message": "Database error occurred"
            }
        ), 500

    return jsonify(
        {
            "status": "success",
            "message": "Invalid credentials"
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
