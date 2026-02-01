# dashboard/dashboard.py

import streamlit as st
import json
import time
import requests
from collections import Counter
from pathlib import Path

LOG_FILE = Path("data/logs/events.log")
CORE_API = "http://127.0.0.1:5001"

st.set_page_config(
    page_title="Behaviour-Aware Honeypot Dashboard",
    layout="wide"
)

st.title("🛡️ Behaviour-Aware Honeypot Dashboard")

# ---------------- HELPERS ----------------

def api_get(path):
    try:
        return requests.get(f"{CORE_API}{path}", timeout=2).json()
    except Exception:
        return {}

def api_post(path):
    try:
        requests.post(f"{CORE_API}{path}", timeout=2)
    except Exception:
        pass

def load_events():
    if not LOG_FILE.exists():
        return []
    events = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events


# ---------------- SIDEBAR CONTROLS ----------------

st.sidebar.header("🎛️ Service Controls")

# ---- HTTP ----
http_running = api_get("/control/http/status").get("running", False)

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

# ---- SSH ----
ssh_running = api_get("/control/ssh/status").get("running", False)

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

refresh_interval = st.sidebar.slider(
    "Refresh interval (seconds)", 1, 10, 3
)

# ---------------- MAIN VIEW ----------------

placeholder = st.empty()

while True:
    with placeholder.container():
        events = load_events()

        behaviour_counts = Counter(
            e.get("behaviour", "UNKNOWN") for e in events
        )

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Events", len(events))
        col2.metric("Automated Attacks", behaviour_counts.get("AUTOMATED_ATTACK", 0))
        col3.metric("Persistent Attackers", behaviour_counts.get("PERSISTENT_ATTACKER", 0))

        st.subheader("🧠 Behaviour Breakdown")
        st.bar_chart(behaviour_counts)

        st.subheader("📜 Recent Events")
        for event in reversed(events[-10:]):
            with st.expander(
                f"{event.get('event_type')} | {event.get('behaviour', 'N/A')}"
            ):
                st.json(event)

    time.sleep(refresh_interval)
