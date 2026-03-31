# dashboard/soc_console.py

import streamlit as st
import json
import time
import requests
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
import pandas as pd

# =========================================================
# CONFIG
# =========================================================

st.set_page_config(
    page_title="Behaviour-Aware Honeypot — SOC Console",
    layout="wide",
)

LOG_FILE = Path("data/logs/events.log")

# Use container name on Docker network, fallback to localhost for local dev
import os
CORE_API = os.environ.get("CORE_API", "http://127.0.0.1:5001")

# =========================================================
# CORE API HELPERS
# =========================================================

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

# =========================================================
# DATA HELPERS
# =========================================================

def load_events():
    if not LOG_FILE.exists():
        return []
    events = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except Exception:
                pass
    return events

def parse_time(ts):
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None

# =========================================================
# SIDEBAR — SERVICE CONTROLS
# =========================================================

st.sidebar.header("🎛 Honeypot Controls")

# ---- HTTP ----
http_status = api_get("/control/http/status")
http_running = http_status.get("running", False)

if http_running:
    st.sidebar.success("HTTP Honeypot: RUNNING")
    if st.sidebar.button("⏹ Stop HTTP"):
        api_post("/control/http/stop")
        st.rerun()
else:
    st.sidebar.warning("HTTP Honeypot: STOPPED")
    if st.sidebar.button("▶ Start HTTP"):
        api_post("/control/http/start")
        st.rerun()

st.sidebar.divider()

# ---- SSH ----
ssh_status = api_get("/control/ssh/status")
ssh_running = ssh_status.get("running", False)

if ssh_running:
    st.sidebar.success("SSH Honeypot: RUNNING")
    if st.sidebar.button("⏹ Stop SSH"):
        api_post("/control/ssh/stop")
        st.rerun()
else:
    st.sidebar.warning("SSH Honeypot: STOPPED")
    if st.sidebar.button("▶ Start SSH"):
        api_post("/control/ssh/start")
        st.rerun()

st.sidebar.divider()

# ---- Core API status indicator ----
if http_status:
    st.sidebar.success("🟢 Core API: CONNECTED")
else:
    st.sidebar.error("🔴 Core API: UNREACHABLE")

st.sidebar.divider()

refresh_interval = st.sidebar.slider(
    "Live refresh (seconds)", 1, 10, 2
)

# =========================================================
# MAIN HEADER
# =========================================================

st.title("🛡 Behaviour-Aware Honeypot — SOC Console")

# =========================================================
# TABS
# =========================================================

tab_overview, tab_live, tab_attackers = st.tabs(
    ["📊 Overview", "🧪 Live Events", "🧑‍💻 Attackers"]
)

# =========================================================
# OVERVIEW TAB
# =========================================================

with tab_overview:
    events = load_events()

    ips = set()
    timeline = defaultdict(int)
    behaviours = []

    for e in events:
        ip = e.get("details", {}).get("client_ip")
        if ip:
            ips.add(ip)

        behaviours.append(e.get("behaviour", "UNKNOWN"))

        ts = parse_time(e.get("timestamp", ""))
        if ts:
            timeline[ts.replace(second=0, microsecond=0)] += 1

    bc = Counter(behaviours)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events", len(events))
    c2.metric("Active Attackers", len(ips))
    c3.metric("Malicious", bc.get("MALICIOUS", 0))
    c4.metric("Confirmed", bc.get("CONFIRMED_ATTACK", 0))

    st.markdown("---")

    if timeline:
        st.subheader("📈 Event Rate")
        st.line_chart(timeline)

    if bc:
        st.subheader("🧠 Behaviour Breakdown")
        st.bar_chart(bc)

# =========================================================
# LIVE EVENTS TAB
# =========================================================

with tab_live:
    st.subheader("🧪 Live Events")

    events = load_events()

    if not events:
        st.info("Waiting for events… Start a honeypot service and trigger some traffic.")
    else:
        rows = []
        for e in reversed(events[-50:]):
            rows.append({
                "Time": e.get("timestamp"),
                "IP": e.get("details", {}).get("client_ip", "N/A"),
                "Event": e.get("event_type"),
                "Behaviour": e.get("behaviour"),
                "Attack": e.get("attack_type"),
                "_raw": e,
            })

        df = pd.DataFrame(rows)

        for _, row in df.iterrows():
            with st.expander(
                f"{row['Time']} | {row['Event']} | {row['IP']} | {row['Behaviour']}"
            ):
                st.json(row["_raw"])

    time.sleep(refresh_interval)
    st.rerun()

# =========================================================
# ATTACKERS TAB
# =========================================================

with tab_attackers:
    attackers = defaultdict(list)
    for e in load_events():
        ip = e.get("details", {}).get("client_ip")
        if ip:
            attackers[ip].append(e)

    if not attackers:
        st.info("No attackers detected yet.")
    else:
        ip = st.selectbox("Select Attacker IP", sorted(attackers.keys()))
        evts = attackers[ip]

        rows = []
        for e in evts:
            rows.append({
                "Time": e.get("timestamp"),
                "Event": e.get("event_type"),
                "Behaviour": e.get("behaviour"),
                "Attack": e.get("attack_type"),
            })

        st.dataframe(pd.DataFrame(rows), use_container_width=True)