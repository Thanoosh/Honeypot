# dashboard/attackers.py

import streamlit as st
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone
import pandas as pd

LOG_FILE = Path("data/logs/events.log")

# ------------------ HELPERS ------------------

def parse_time(ts):
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


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
    return events


def risk_from_behaviour(behaviour):
    if behaviour == "CONFIRMED_ATTACK":
        return "🔴 HIGH"
    if behaviour == "MALICIOUS":
        return "🟠 MEDIUM"
    if behaviour == "SUSPICIOUS":
        return "🟡 LOW"
    return "🟢 NORMAL"


# ------------------ UI ------------------

def render_attackers():
    st.title("🧑‍💻 Attackers — Behaviour Profiles")
    st.caption("Entity-centric view of attacker behaviour (SOC / SIEM style)")

    events = load_events()

    if not events:
        st.warning("No events logged yet.")
        return

    attackers = defaultdict(lambda: {
        "events": 0,
        "first_seen": None,
        "last_seen": None,
        "behaviour": "NEW",
        "max_confidence": 0.0,
        "attack_types": set(),
        "raw": [],
    })

    # ------------------ AGGREGATION ------------------

    for e in events:
        ip = e.get("details", {}).get("client_ip")
        if not ip:
            continue

        ts = parse_time(e.get("timestamp", ""))
        behaviour = e.get("behaviour", "UNKNOWN")
        confidence = float(e.get("confidence", 0.0))
        attack_type = e.get("attack_type", "UNKNOWN")

        a = attackers[ip]
        a["events"] += 1
        a["raw"].append(e)

        if ts:
            if not a["first_seen"] or ts < a["first_seen"]:
                a["first_seen"] = ts
            if not a["last_seen"] or ts > a["last_seen"]:
                a["last_seen"] = ts

        # highest behaviour wins
        priority = ["NEW", "PROBING", "SUSPICIOUS", "MALICIOUS", "CONFIRMED_ATTACK"]
        if priority.index(behaviour) > priority.index(a["behaviour"]):
            a["behaviour"] = behaviour

        a["max_confidence"] = max(a["max_confidence"], confidence)

        if attack_type != "BENIGN":
            a["attack_types"].add(attack_type)

    # ------------------ TABLE DATA ------------------

    rows = []
    for ip, a in attackers.items():
        rows.append({
            "IP Address": ip,
            "Total Events": a["events"],
            "Behaviour": a["behaviour"],
            "Risk": risk_from_behaviour(a["behaviour"]),
            "Max Confidence": round(a["max_confidence"], 2),
            "Attack Types": ", ".join(sorted(a["attack_types"])) or "None",
            "First Seen": a["first_seen"].strftime("%Y-%m-%d %H:%M:%S") if a["first_seen"] else "N/A",
            "Last Seen": a["last_seen"].strftime("%Y-%m-%d %H:%M:%S") if a["last_seen"] else "N/A",
            "_raw": a["raw"],
        })

    df = pd.DataFrame(rows).sort_values(
        by=["Risk", "Total Events"], ascending=[False, False]
    )

    # ------------------ FILTERS ------------------

    with st.expander("🔎 Filters", expanded=True):
        behaviours = st.multiselect(
            "Behaviour",
            sorted(df["Behaviour"].unique()),
            default=sorted(df["Behaviour"].unique()),
        )

    df = df[df["Behaviour"].isin(behaviours)]

    # ------------------ DISPLAY ------------------

    st.subheader(f"🧾 Attackers Detected ({len(df)})")

    st.dataframe(
        df.drop(columns=["_raw"]),
        width="stretch",
        height=450,
    )

    # ------------------ INSPECTOR ------------------

    st.markdown("---")
    st.subheader("🧪 Attacker Event History")

    selected_ip = st.selectbox("Select attacker IP", df["IP Address"])

    raw_events = df[df["IP Address"] == selected_ip]["_raw"].iloc[0]

    for e in sorted(raw_events, key=lambda x: x.get("timestamp", ""), reverse=True):
        with st.expander(
            f"{e.get('timestamp')} | {e.get('event_type')} | {e.get('behaviour')}"
        ):
            st.json(e)


# ------------------ ENTRY ------------------

if __name__ == "__main__":
    render_attackers()
