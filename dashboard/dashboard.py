import os
import streamlit as st
import json
import time
import requests
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime, timezone

LOG_FILE = Path("data/logs/events.log")

# ✅ FIX: Always resolve correct CORE API
CORE_API = os.environ.get("CORE_API")
if not CORE_API:
    CORE_API = "http://honeypot_core:5001"

st.set_page_config(
    page_title="Behaviour-Aware Honeypot Dashboard",
    layout="wide",
)

st.title("🛡️ Behaviour-Aware Honeypot Dashboard")

# ─────────────────────────────────────────────
# HELPERS (HARDENED)
# ─────────────────────────────────────────────

def api_get(path):
    try:
        url = f"{CORE_API}{path}"
        r = requests.get(
            url,
            timeout=5,
            headers={"Host": "localhost:5001"}  # ✅ CRITICAL FIX
        )

        if r.status_code == 200:
            return r.json()

        print(f"[DASHBOARD] GET FAILED {url} → {r.status_code}")
        return {}

    except Exception as e:
        print(f"[DASHBOARD] GET ERROR: {e}")
        return {}


def api_post(path):
    try:
        url = f"{CORE_API}{path}"
        r = requests.post(
            url,
            timeout=5,
            headers={"Host": "localhost:5001"}  # ✅ CRITICAL FIX
        )

        print(f"[DASHBOARD] POST {url} → {r.status_code}")

    except Exception as e:
        print(f"[DASHBOARD] POST ERROR: {e}")


def load_events():
    if not LOG_FILE.exists():
        return []

    events = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except:
                pass
    return events


def parse_time(ts):
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except:
        return None


# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────

st.sidebar.header("🎛️ Service Controls")

http_status = api_get("/control/http/status")
http_running = http_status.get("running", False)
docker_ok = http_status.get("docker_available", False)

if http_running:
    st.sidebar.success("HTTP Honeypot: RUNNING")
    if st.sidebar.button("⏹ Stop HTTP Honeypot"):
        api_post("/control/http/stop")
        st.rerun()
else:
    st.sidebar.warning("HTTP Honeypot: STOPPED")
    if st.sidebar.button("▶ Start HTTP Honeypot"):
        api_post("/control/http/start")
        st.rerun()

st.sidebar.divider()

ssh_status = api_get("/control/ssh/status")
ssh_running = ssh_status.get("running", False)

if ssh_running:
    st.sidebar.success("SSH Honeypot: RUNNING")
    if st.sidebar.button("⏹ Stop SSH Honeypot"):
        api_post("/control/ssh/stop")
        st.rerun()
else:
    st.sidebar.warning("SSH Honeypot: STOPPED")
    if st.sidebar.button("▶ Start SSH Honeypot"):
        api_post("/control/ssh/start")
        st.rerun()

st.sidebar.divider()

if http_status:
    st.sidebar.success("🟢 Core API: CONNECTED")
    if docker_ok:
        st.sidebar.success("🟢 Docker: AVAILABLE")
    else:
        st.sidebar.error("🔴 Docker: UNAVAILABLE")
else:
    st.sidebar.error("🔴 Core API: UNREACHABLE")

refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 1, 10, 3)

# ─────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────

placeholder = st.empty()

while True:
    with placeholder.container():

        events = load_events()

        behaviour_counts = Counter(e.get("behaviour", "UNKNOWN") for e in events)

        attacker_ips = {
            e.get("details", {}).get("client_ip")
            for e in events if e.get("details", {}).get("client_ip")
        }

        timeline = defaultdict(int)
        for e in events:
            ts = parse_time(e.get("timestamp", ""))
            if ts:
                timeline[ts.replace(second=0, microsecond=0)] += 1

        c1, c2, c3 = st.columns(3)
        c1.metric("Events", len(events))
        c2.metric("Attackers", len(attacker_ips))
        c3.metric("Malicious", behaviour_counts.get("MALICIOUS", 0))

        st.bar_chart(behaviour_counts)
        st.line_chart(timeline)

    time.sleep(refresh_interval)