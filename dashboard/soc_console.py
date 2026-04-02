# dashboard/soc_console.py

import streamlit as st
import json
import time
import requests
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
import pandas as pd
import os

# =========================================================
# CONFIG
# =========================================================

st.set_page_config(
    page_title="Behaviour-Aware Honeypot — SOC Console",
    layout="wide",
)

LOG_FILE = Path("data/logs/events.log")

CORE_API = os.environ.get("CORE_API", "http://honeypot_core:5001")

BEHAVIOUR_COLORS = {
    "NEW":                  "#6c757d",
    "PROBING":              "#0dcaf0",
    "SUSPICIOUS":           "#ffc107",
    "MALICIOUS":            "#fd7e14",
    "CONFIRMED_ATTACK":     "#dc3545",
    "KILL_CHAIN_CONFIRMED": "#9d00ff",
}

STATE_PRIORITY = [
    "NEW", "PROBING", "SUSPICIOUS",
    "MALICIOUS", "CONFIRMED_ATTACK", "KILL_CHAIN_CONFIRMED"
]

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
# STYLE HELPER — compatible with all pandas versions
# Uses .style.apply (column-level) instead of deprecated applymap
# =========================================================

def colour_behaviour_column(series):
    return [
        f"color: {BEHAVIOUR_COLORS.get(v, '#adb5bd')}; font-weight: bold"
        for v in series
    ]

# =========================================================
# DATAFRAME HELPER — compatible with old and new Streamlit
# New Streamlit (>=1.40) deprecated use_container_width
# This helper tries the new API first, falls back to the old one
# =========================================================

def show_dataframe(df_or_styled, height=None):
    kwargs = {"height": height} if height else {}
    # Use modern width='stretch' to avoid deprecation warnings
    st.dataframe(df_or_styled, width="stretch", **kwargs)

# =========================================================
# SIDEBAR — SERVICE CONTROLS
# =========================================================

st.sidebar.header("🎛 Honeypot Controls")

# ---- HTTP ----
http_status = api_get("/control/http/status")
http_running = http_status.get("running", False)
docker_available = http_status.get("docker_available", True)

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

# ---- Core API + Docker status ----
if http_status:
    st.sidebar.success("🟢 Core API: CONNECTED")
    if not docker_available:
        st.sidebar.error("🔴 Docker: NOT AVAILABLE\nMount /var/run/docker.sock")
    else:
        st.sidebar.success("🟢 Docker: AVAILABLE")
else:
    st.sidebar.error("🔴 Core API: UNREACHABLE")

st.sidebar.divider()

refresh_interval = st.sidebar.slider(
    "Live refresh (seconds)", 1, 10, 3
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
    kill_chain_ips = set()

    for e in events:
        ip = e.get("details", {}).get("client_ip")
        if ip:
            ips.add(ip)

        b = e.get("behaviour", "UNKNOWN")
        behaviours.append(b)

        if b == "KILL_CHAIN_CONFIRMED":
            kill_chain_ips.add(ip)

        ts = parse_time(e.get("timestamp", ""))
        if ts:
            timeline[ts.replace(second=0, microsecond=0)] += 1

    bc = Counter(behaviours)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Events",     len(events))
    c2.metric("Active Attackers", len(ips))
    c3.metric("Malicious",        bc.get("MALICIOUS", 0))
    c4.metric("Confirmed",        bc.get("CONFIRMED_ATTACK", 0))
    c5.metric("🔴 Kill Chain",    len(kill_chain_ips))

    if kill_chain_ips:
        st.error(
            f"⚠️ KILL CHAIN CONFIRMED — {len(kill_chain_ips)} attacker(s) "
            f"completed full HTTP → SSH attack chain: {', '.join(kill_chain_ips)}"
        )

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

    live_events = load_events()

    if not live_events:
        st.info("Waiting for events… Start a honeypot service and trigger some traffic.")
    else:
        rows = []
        for e in reversed(live_events[-50:]):
            rows.append({
                "Time":      e.get("timestamp", ""),
                "IP":        e.get("details", {}).get("client_ip", "N/A"),
                "Event":     e.get("event_type", ""),
                "Behaviour": e.get("behaviour", "UNKNOWN"),
                "Attack":    e.get("attack_type", ""),
                "Risk":      e.get("risk_score", 0.0),
                "_raw":      e,
            })

        df_live = pd.DataFrame(rows)

        styled_live = (
            df_live.drop(columns=["_raw"])
            .style.apply(colour_behaviour_column, subset=["Behaviour"])
        )
        show_dataframe(styled_live, height=400)

        st.markdown("---")
        st.subheader("🧾 Event Inspector")

        if rows:
            selected_idx = st.selectbox(
                "Select event to inspect",
                range(len(rows)),
                format_func=lambda i: (
                    f"{rows[i]['Time']} | {rows[i]['Event']} | {rows[i]['IP']}"
                ),
            )
            st.json(rows[selected_idx]["_raw"])

# =========================================================
# ATTACKERS TAB
# =========================================================

with tab_attackers:
    all_events = load_events()
    attackers = defaultdict(list)
    for e in all_events:
        ip = e.get("details", {}).get("client_ip")
        if ip:
            attackers[ip].append(e)

    if not attackers:
        st.info("No attackers detected yet.")
    else:
        attacker_rows = []
        for ip, evts in attackers.items():
            highest_state = "NEW"
            for e in evts:
                b = e.get("behaviour", "NEW")
                if b in STATE_PRIORITY:
                    if STATE_PRIORITY.index(b) > STATE_PRIORITY.index(highest_state):
                        highest_state = b

            attack_types = ", ".join(
                {e.get("attack_type", "") for e in evts
                 if e.get("attack_type") not in ("BENIGN", "", None)}
            ) or "None"

            attacker_rows.append({
                "IP":           ip,
                "Events":       len(evts),
                "Behaviour":    highest_state,
                "Attack Types": attack_types,
                "Kill Chain":   "✅ COMPLETE" if highest_state == "KILL_CHAIN_CONFIRMED" else "❌",
            })

        df_attackers = pd.DataFrame(attacker_rows)

        styled_attackers = df_attackers.style.apply(
            colour_behaviour_column, subset=["Behaviour"]
        )
        show_dataframe(styled_attackers, height=300)

        st.markdown("---")

        selected_ip = st.selectbox("Select Attacker IP", sorted(attackers.keys()))
        evts_for_ip = attackers[selected_ip]

        event_rows = []
        for e in evts_for_ip:
            event_rows.append({
                "Time":      e.get("timestamp", ""),
                "Event":     e.get("event_type", ""),
                "Behaviour": e.get("behaviour", ""),
                "Attack":    e.get("attack_type", ""),
                "Risk":      e.get("risk_score", 0.0),
            })

        show_dataframe(pd.DataFrame(event_rows))

        st.markdown("---")
        st.subheader("🔍 Raw Event History")
        for e in sorted(evts_for_ip, key=lambda x: x.get("timestamp", ""), reverse=True)[:20]:
            with st.expander(
                f"{e.get('timestamp', '')} | {e.get('event_type', '')} | {e.get('behaviour', '')}"
            ):
                st.json(e)

# =========================================================
# AUTO REFRESH — outside all tabs to avoid segfault
# =========================================================

time.sleep(refresh_interval)
st.rerun()