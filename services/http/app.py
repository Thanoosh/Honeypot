# services/http/app.py
#
# NovaTech Solutions — Decoy Company Website
# Every endpoint is a honeypot trap.
# All interactions are logged to Core API for behaviour analysis.
# Vulnerable by design — SQL errors, exposed files, leaked credentials.

import os
import re
import time
import requests
from datetime import datetime
from flask import Flask, request, jsonify, render_template, Response

app = Flask(__name__)

# ─────────────────────────────────────────────
# CONFIG
# FIX #2: Use environment variable for core endpoint.
# Inside Docker the service name is 'honeypot_core'.
# For local dev without Docker, falls back to 127.0.0.1.
# host.docker.internal only works on Docker Desktop (Windows/Mac),
# NOT on Linux — so we remove that dependency entirely.
# ─────────────────────────────────────────────

CORE_EVENT_ENDPOINT = os.environ.get(
    "CORE_API", "http://honeypot_core:5001"
) + "/event"

SERVICE_MODE = "NORMAL"

# SSH Easter egg credentials — must match ssh_honeypot.py KILL_CHAIN_PASSWORD
LEAKED_SSH_HOST = "prod-server-01"
LEAKED_SSH_PORT = "2222"
LEAKED_SSH_USER = "admin"
LEAKED_SSH_PASS = "Adm1n#2024"

# ─────────────────────────────────────────────
# ATTACK DETECTION PATTERNS
# ─────────────────────────────────────────────

SQLI_PATTERNS = [
    r"(?i)union\s+select",
    r"(?i)or\s+1\s*=\s*1",
    r"(?i)'\s*or\s*'",
    r"(?i)--\s*$",
    r"(?i)sleep\s*\(",
    r"(?i)drop\s+table",
    r"(?i)insert\s+into",
    r"(?i)benchmark\s*\(",
    r"(?i);\s*select",
    r"(?i)'\s*;\s*",
]

XSS_PATTERNS = [
    r"(?i)<script.*?>",
    r"(?i)javascript\s*:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)<iframe",
    r"(?i)alert\s*\(",
    r"(?i)document\.cookie",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%252e%252e",
    r"etc/passwd",
    r"windows/system32",
]

SCANNER_HEADERS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab",
    "python-requests", "go-http-client", "curl",
]

# ─────────────────────────────────────────────
# MITRE ATT&CK MAPPING
# ─────────────────────────────────────────────

MITRE_MAP = {
    "SQL_INJECTION":    {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "XSS":              {"id": "T1059.007", "name": "JavaScript Execution"},
    "PATH_TRAVERSAL":   {"id": "T1083", "name": "File and Directory Discovery"},
    "RECON_SCAN":       {"id": "T1595.002", "name": "Vulnerability Scanning"},
    "CRED_ACCESS":      {"id": "T1552.001", "name": "Credentials in Files"},
    "BRUTE_FORCE":      {"id": "T1110", "name": "Brute Force"},
    "KILL_CHAIN":       {"id": "T1078", "name": "Valid Accounts"},
}

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def detect_sqli(payload: str) -> bool:
    return any(re.search(p, payload) for p in SQLI_PATTERNS)

def detect_xss(payload: str) -> bool:
    return any(re.search(p, payload) for p in XSS_PATTERNS)

def detect_path_traversal(payload: str) -> bool:
    return any(re.search(p, payload) for p in PATH_TRAVERSAL_PATTERNS)

def detect_scanner() -> bool:
    ua = request.headers.get("User-Agent", "").lower()
    return any(s in ua for s in SCANNER_HEADERS)

def get_client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr)

def send_event(event_type: str, details: dict, mitre_id: str = "", mitre_name: str = "") -> dict:
    """
    Send event to Core API and return the enriched decision.
    FIX #9: No longer silently swallows errors — prints a warning so
    you can see in Docker logs if the core API is unreachable.
    """
    global SERVICE_MODE
    try:
        payload = {
            "event_type": event_type,
            "details": {
                **details,
                "client_ip": get_client_ip(),
                "user_agent": request.headers.get("User-Agent", ""),
                "endpoint": request.path,
                "method": request.method,
            },
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
        }
        resp = requests.post(
            CORE_EVENT_ENDPOINT,
            json=payload,
            timeout=3,
            headers={"Host": "localhost:5001"}
        )
        if resp.ok:
            result = resp.json()
            response = result.get("response", {})
            SERVICE_MODE = response.get("service_mode", SERVICE_MODE)
            delay = response.get("delay", 0)
            if delay > 0:
                time.sleep(delay)
            return result
        else:
            print(f"[HTTP][WARN] Core API returned {resp.status_code} for event {event_type}")
    except requests.exceptions.ConnectionError:
        print(f"[HTTP][WARN] Cannot reach Core API at {CORE_EVENT_ENDPOINT} — event {event_type} dropped")
    except requests.exceptions.Timeout:
        print(f"[HTTP][WARN] Core API timeout — event {event_type} dropped")
    except Exception as e:
        print(f"[HTTP][WARN] send_event failed for {event_type}: {e}")
    return {}

# ─────────────────────────────────────────────
# FAKE SERVER HEADERS
# Makes the server look like a real Apache/PHP stack
# ─────────────────────────────────────────────

@app.after_request
def add_fake_headers(response):
    response.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    response.headers["X-Powered-By"] = "PHP/7.4.3"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response

# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    if detect_scanner():
        send_event("HTTP_SCANNER_DETECTED", {
            "user_agent": request.headers.get("User-Agent", ""),
        }, **MITRE_MAP["RECON_SCAN"])
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("index.html", page="about")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    username = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        combined = f"{username} {password}"

        # SQLi detection
        if detect_sqli(combined):
            send_event("HTTP_SQLI_ATTEMPT", {
                "endpoint": "/login",
                "payload": combined,
                "username": username,
            }, **MITRE_MAP["SQL_INJECTION"])

            # Deception — fake SQL error that leaks table info
            if SERVICE_MODE in ("DECEPTION", "FAKE_DB"):
                error = "SQL Error: You have an error in your SQL syntax near 'users' at line 1. Table: novatech_users, Column: password_hash"
            else:
                error = "Database error: Query failed near syntax error"

            return render_template("login.html", error=error, username=username)

        # XSS detection
        if detect_xss(combined):
            send_event("HTTP_XSS_ATTEMPT", {
                "endpoint": "/login",
                "payload": combined,
            }, **MITRE_MAP["XSS"])
            error = "Invalid input detected."
            return render_template("login.html", error=error, username=username)

        # Brute force — log all login attempts
        send_event("HTTP_LOGIN_ATTEMPT", {
            "username": username,
            "endpoint": "/login",
        }, **MITRE_MAP["BRUTE_FORCE"])

        error = "Invalid username or password."
        return render_template("login.html", error=error, username=username)

    return render_template("login.html", error=None, username="")


@app.route("/portal")
def portal():
    send_event("HTTP_PORTAL_ACCESS", {
        "endpoint": "/portal",
    }, **MITRE_MAP["RECON_SCAN"])
    return render_template("portal.html")


@app.route("/admin")
def admin():
    send_event("HTTP_ADMIN_PROBE", {
        "endpoint": "/admin",
    }, **MITRE_MAP["RECON_SCAN"])
    return render_template("admin.html"), 403


@app.route("/backup")
def backup():
    send_event("HTTP_BACKUP_ACCESS", {
        "endpoint": "/backup",
        "high_value": True,
    }, **MITRE_MAP["CRED_ACCESS"])
    return render_template("backup.html")


@app.route("/backup/<filename>")
def backup_file(filename):
    """Serve fake backup files — Easter egg trail."""

    send_event("HTTP_BACKUP_FILE_ACCESS", {
        "endpoint": f"/backup/{filename}",
        "filename": filename,
        "high_value": True,
    }, **MITRE_MAP["CRED_ACCESS"])

    if filename == "server_info.txt":
        content = f"""NovaTech Solutions — Server Information
========================================
Environment : Production
Server      : {LEAKED_SSH_HOST}
OS          : Ubuntu 20.04.6 LTS
SSH Port    : {LEAKED_SSH_PORT}
SSH User    : {LEAKED_SSH_USER}

NOTE: Default credentials still in use on prod-server-01.
Ticket #4821 open to rotate. Low priority.
"""
        return Response(content, mimetype="text/plain")

    elif filename == "db_backup_nov.sql":
        content = """-- NovaTech Production Database Backup
-- Generated: 2024-11-01 02:00:01
-- Host: prod-db-01.internal

CREATE TABLE novatech_users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(50),
  email VARCHAR(100),
  password_hash VARCHAR(255),
  role ENUM('user','admin','superadmin'),
  created_at TIMESTAMP
);

INSERT INTO novatech_users VALUES
(1,'admin','admin@novatech.internal','$2b$12$LQv3c1yqBWVHxkd0LHAkCO','superadmin','2023-01-10'),
(2,'j.smith','j.smith@novatech.com','$2b$12$EixZaYVK1fsbw1ZfbX3OXe','admin','2023-04-15'),
(3,'deploy','deploy@novatech.internal','$2b$12$N9qo8uLOickgx2ZMRZoMye','deploy','2023-06-01');
"""
        return Response(content, mimetype="text/plain")

    elif filename == "config_backup.tar.gz":
        return Response(
            "Archive corrupt. Last known config: DB_HOST=prod-db-01.internal, DB_PASS=N0vaTech#DB2024",
            mimetype="text/plain"
        )

    return Response("File not found.", mimetype="text/plain"), 404


@app.route("/.env")
def env_file():
    """
    The crown jewel Easter egg.
    Attacker finds this and gets SSH credentials.
    This is the kill chain trigger.
    """
    send_event("HTTP_ENV_FILE_ACCESS", {
        "endpoint": "/.env",
        "high_value": True,
        "kill_chain_stage": "CREDENTIAL_EXPOSURE",
    }, **MITRE_MAP["CRED_ACCESS"])

    content = f"""# NovaTech Solutions — Production Environment
# WARNING: Do not commit this file

APP_ENV=production
APP_DEBUG=false
APP_SECRET_KEY=n0v@T3ch_s3cr3t_2024!
APP_URL=https://portal.novatech.com

# Database
DB_HOST=prod-db-01.internal
DB_PORT=3306
DB_NAME=novatech_prod
DB_USER=novatech_app
DB_PASS=N0vaTech#DB2024

# Redis
REDIS_HOST=cache-01.internal
REDIS_PORT=6379
REDIS_PASS=r3d1s_n0va_2024

# SSH Access (prod server)
SSH_HOST={LEAKED_SSH_HOST}
SSH_PORT={LEAKED_SSH_PORT}
SSH_USER={LEAKED_SSH_USER}
SSH_PASS={LEAKED_SSH_PASS}

# AWS
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1

# Stripe
STRIPE_SECRET=sk_live_FAKEKEY1234567890abcdefgh
"""
    return Response(content, mimetype="text/plain")


@app.route("/robots.txt")
def robots():
    """
    Plants breadcrumbs for attackers.
    Every good attacker checks robots.txt first.
    """
    send_event("HTTP_ROBOTS_ACCESS", {
        "endpoint": "/robots.txt",
    }, **MITRE_MAP["RECON_SCAN"])

    content = """User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /internal
Disallow: /api/internal
Disallow: /.env
Disallow: /config

# Portal
Allow: /portal
Allow: /login
"""
    return Response(content, mimetype="text/plain")


@app.route("/api/users")
def api_users():
    """Fake API endpoint — leaks user data."""
    send_event("HTTP_API_PROBE", {
        "endpoint": "/api/users",
        "high_value": True,
    }, **MITRE_MAP["RECON_SCAN"])

    return jsonify({
        "status": "error",
        "message": "Authentication required",
        "debug": {
            "users_table": "novatech_users",
            "total_users": 47,
            "admin_count": 3,
        }
    }), 401


@app.route("/api/users/<int:user_id>")
def api_user(user_id):
    send_event("HTTP_API_USER_ENUM", {
        "endpoint": f"/api/users/{user_id}",
        "user_id": user_id,
    }, **MITRE_MAP["RECON_SCAN"])

    fake_users = {
        1: {"id": 1, "username": "admin", "email": "admin@novatech.internal", "role": "superadmin"},
        2: {"id": 2, "username": "j.smith", "email": "j.smith@novatech.com", "role": "admin"},
        3: {"id": 3, "username": "deploy", "email": "deploy@novatech.internal", "role": "deploy"},
    }
    user = fake_users.get(user_id)
    if user:
        return jsonify(user)
    return jsonify({"error": "User not found"}), 404


@app.route("/search")
def search():
    query = request.args.get("q", "")
    if not query:
        return render_template("index.html")

    combined = query

    if detect_sqli(combined):
        send_event("HTTP_SQLI_ATTEMPT", {
            "endpoint": "/search",
            "payload": combined,
        }, **MITRE_MAP["SQL_INJECTION"])
        return jsonify({"error": "Search error: syntax error in query"}), 500

    if detect_xss(combined):
        send_event("HTTP_XSS_ATTEMPT", {
            "endpoint": "/search",
            "payload": combined,
        }, **MITRE_MAP["XSS"])
        return jsonify({"results": [], "query": query})

    if detect_path_traversal(combined):
        send_event("HTTP_PATH_TRAVERSAL", {
            "endpoint": "/search",
            "payload": combined,
        }, **MITRE_MAP["PATH_TRAVERSAL"])
        return jsonify({"error": "Invalid search query"}), 400

    return jsonify({"results": [], "query": query, "total": 0})


@app.route("/download")
def download():
    filepath = request.args.get("file", "")
    if detect_path_traversal(filepath):
        send_event("HTTP_PATH_TRAVERSAL", {
            "endpoint": "/download",
            "payload": filepath,
            "high_value": True,
        }, **MITRE_MAP["PATH_TRAVERSAL"])
        return jsonify({"error": "Access denied: invalid file path"}), 403
    return jsonify({"error": "File not found"}), 404


# Catch all unknown paths — log directory scanning
@app.route("/<path:path>")
def catch_all(path):
    send_event("HTTP_UNKNOWN_PATH", {
        "endpoint": f"/{path}",
    }, **MITRE_MAP["RECON_SCAN"])
    return render_template("index.html"), 404


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[HTTP] NovaTech decoy website starting on port 8080...")
    print(f"[HTTP] Core API endpoint: {CORE_EVENT_ENDPOINT}")
    app.run(host="0.0.0.0", port=8080, debug=False)