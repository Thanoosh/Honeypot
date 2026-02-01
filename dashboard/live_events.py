# dashboard/live_events.py

import streamlit as st
import json
from pathlib import Path
from datetime import datetime, timezone
import pandas as pd

LOG_FILE = Path("data/logs/events.log")

# ------------------ CONFIG ------------------

MAX_EVENTS = 200
REFRESH_SECONDS = 3

BEHAVIOUR_COLORS = {
    "NEW": "#6c757d",
    "PROBING": "#0dcaf0",
    "SUSPICIOUS": "#ffc107",
    "MALICIOUS": "#fd7e14",
    "CONFIRMED_ATTACK": "#dc3545",
}

# ------------------ DATA LOADER ------------------

def load_events():
    if not LOG_FILE.exists():
        return []

    events = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except Exception:
                continue

    return events[-MAX_EVENTS:]


def normalize_event(e):
    return {
        "Time": e.get("timestamp"),
        "IP": e.get("details", {}).get("client_ip", "N/A"),
        "Event Type": e.get("event_type", "UNKNOWN"),
        "Attack Type": e.get("attack_type", "UNKNOWN"),
        "Behaviour": e.get("behaviour", "UNKNOWN"),
        "Confidence": round(float(e.get("confidence", 0.0)), 2),
        "Raw": e,
    }

# ------------------ UI ------------------

def render_live_events():
    st.title("🧪 Live Events — SOC Console")

    st.caption("Real-time security event stream from the honeypot")

    # Auto refresh
    st.markdown(
        f"""
        <meta http-equiv="refresh" content="{REFRESH_SECONDS}">
        """,
        unsafe_allow_html=True,
    )

    events = load_events()

    if not events:
        st.warning("No events logged yet.")
        return

    normalized = [normalize_event(e) for e in events]
    df = pd.DataFrame(normalized)

    # ------------------ FILTERS ------------------

    with st.expander("🔎 Filters", expanded=True):
        col1, col2, col3 = st.columns(3)

        with col1:
            behaviour_filter = st.multiselect(
                "Behaviour",
                sorted(df["Behaviour"].unique()),
                default=sorted(df["Behaviour"].unique()),
            )

        with col2:
            event_filter = st.multiselect(
                "Event Type",
                sorted(df["Event Type"].unique()),
                default=sorted(df["Event Type"].unique()),
            )

        with col3:
            attack_filter = st.multiselect(
                "Attack Type",
                sorted(df["Attack Type"].unique()),
                default=sorted(df["Attack Type"].unique()),
            )

    filtered = df[
        (df["Behaviour"].isin(behaviour_filter))
        & (df["Event Type"].isin(event_filter))
        & (df["Attack Type"].isin(attack_filter))
    ]

    # ------------------ TABLE ------------------

    st.subheader(f"📡 Latest Events ({len(filtered)})")

    def style_behaviour(val):
        color = BEHAVIOUR_COLORS.get(val, "#adb5bd")
        return f"color: {color}; font-weight: bold"

    styled = (
        filtered.drop(columns=["Raw"])
        .sort_values("Time", ascending=False)
        .style.applymap(style_behaviour, subset=["Behaviour"])
    )

    st.dataframe(
        styled,
        use_container_width=True,
        height=450,
    )

    # ------------------ RAW EVENT VIEW ------------------

    st.markdown("---")
    st.subheader("🧾 Event Inspector")

    selected = st.selectbox(
        "Select event to inspect",
        filtered.index[::-1],
        format_func=lambda i: f"{filtered.loc[i]['Time']} | {filtered.loc[i]['Event Type']} | {filtered.loc[i]['IP']}",
    )

    st.json(filtered.loc[selected]["Raw"])


# ------------------ ENTRY ------------------

if __name__ == "__main__":
    render_live_events()
