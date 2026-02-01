# dashboard/overview.py

import streamlit as st
import json
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter, defaultdict

LOG_FILE = Path("data/logs/events.log")

# ---------------- LOAD DATA ----------------

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


# ---------------- STYLES ----------------

def apply_styles():
    st.markdown("""
    <style>
    html, body, [class*="css"]  {
        background-color: #0b1220;
    }
    .panel {
        background: #0f172a;
        border-radius: 12px;
        padding: 16px;
        border: 1px solid rgba(255,255,255,0.05);
    }
    .kpi {
        font-size: 28px;
        font-weight: 700;
    }
    .kpi-label {
        color: #94a3b8;
        font-size: 13px;
    }
    </style>
    """, unsafe_allow_html=True)


# ---------------- MAIN RENDER ----------------

def render_overview():
    apply_styles()

    events = load_events()
    if not events:
        st.warning("No events logged yet.")
        return

    ips = set()
    behaviours = []
    last_seen = None
    timeline = defaultdict(int)

    for e in events:
        ip = e.get("details", {}).get("client_ip")
        if ip:
            ips.add(ip)

        b = e.get("behaviour", "UNKNOWN")
        behaviours.append(b)

        ts = parse_time(e.get("timestamp", ""))
        if ts:
            last_seen = max(last_seen, ts) if last_seen else ts
            timeline[ts.replace(second=0, microsecond=0)] += 1

    behaviour_count = Counter(behaviours)
    total = len(events)

    suspicious = sum(
        behaviour_count.get(k, 0)
        for k in ["SUSPICIOUS", "MALICIOUS", "CONFIRMED_ATTACK"]
    )

    now = datetime.now(timezone.utc)
    last_delta = f"{int((now - last_seen).total_seconds())}s ago" if last_seen else "N/A"

    # ---------------- KPI ROW ----------------

    c1, c2, c3, c4, c5 = st.columns(5)

    def kpi(col, label, value):
        col.markdown(f"""
        <div class="panel">
            <div class="kpi">{value}</div>
            <div class="kpi-label">{label}</div>
        </div>
        """, unsafe_allow_html=True)

    kpi(c1, "Total Events", total)
    kpi(c2, "Active Attackers", len(ips))
    kpi(c3, "Suspicious+", suspicious)
    kpi(c4, "Confirmed Attacks", behaviour_count.get("CONFIRMED_ATTACK", 0))
    kpi(c5, "Last Event", last_delta)

    st.markdown("<br>", unsafe_allow_html=True)

    # ---------------- CHART ROW ----------------

    left, right = st.columns([2, 1])

    with left:
        st.markdown("<div class='panel'>", unsafe_allow_html=True)
        st.markdown("**Event Rate (last minutes)**")
        st.line_chart(timeline)
        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        st.markdown("<div class='panel'>", unsafe_allow_html=True)
        st.markdown("**Behaviour Distribution**")
        st.bar_chart(behaviour_count)
        st.markdown("</div>", unsafe_allow_html=True)
