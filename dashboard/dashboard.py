import os
import streamlit as st
import pandas as pd
import json
import time
import requests
import hashlib
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime, timezone

# ---------------- CONFIG ----------------
LOG_FILE = Path("data/logs/events.log")

# ✅ FIX: Always resolve correct CORE API
CORE_API = os.environ.get("CORE_API")
if not CORE_API:
    CORE_API = "http://honeypot_core:5001"

st.set_page_config(
    page_title="Honeypot SOC Premium",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- PREMIUM CSS (Glassmorphism & Alignment) ----------------
# We use a curated dark theme with glassmorphism and specialized metrics.
st.markdown("""
<style>

/* ===== GLOBAL BACKGROUND ===== */
.stApp {
    background: radial-gradient(circle at top left, #0e1117, #05070d 80%);
    color: #e6edf3;
    font-family: 'Inter', sans-serif;
}

/* ===== METRIC CARDS (Enhanced Glassmorphism) ===== */
[data-testid="stMetric"] {
    background: rgba(255, 255, 255, 0.03) !important;
    padding: 24px !important;
    border-radius: 20px !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    backdrop-filter: blur(15px) saturate(180%) !important;
    transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) !important;
    position: relative;
    overflow: hidden;
    height: 160px !important; 
    display: flex;
    flex-direction: column;
    justify-content: center;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
}

/* Glow hover effect */
[data-testid="stMetric"]:hover {
    transform: translateY(-8px) scale(1.03);
    border: 1px solid rgba(0, 212, 255, 0.8) !important;
    box-shadow: 0 0 30px rgba(0, 212, 255, 0.3);
}

/* Neon accents */
[data-testid="stMetric"]::before {
    content: "";
    position: absolute;
    top: 0;
    left: 0;
    height: 4px;
    width: 100%;
    background: linear-gradient(90deg, #00d4ff, #7f5af0, #ff4b4b);
}

/* Metric Value Styling */
div[data-testid="stMetricValue"] {
    font-size: 2.2rem !important;
    font-weight: 900 !important;
    background: linear-gradient(135deg, #00d4ff, #7f5af0);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -1px;
}

/* Metric Label Styling */
div[data-testid="stMetricLabel"] {
    font-size: 0.9rem !important;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: #8892a0 !important;
    font-weight: 600 !important;
}

/* ===== CONTAINERS & ALIGNMENT ===== */
[data-testid="column"] {
    width: calc(20% - 1rem) !important;
    min-width: 150px !important;
    flex: 1 1 auto !important;
}

/* ===== TABS (Modernized) ===== */
.stTabs [data-baseweb="tab-list"] {
    gap: 40px;
    border-bottom: 2px solid rgba(255,255,255,0.05);
    margin-bottom: 30px;
}

.stTabs [data-baseweb="tab"] {
    height: 60px;
    color: #8892a0;
    font-size: 18px;
    font-weight: 500;
    transition: all 0.3s ease;
}

.stTabs [aria-selected="true"] {
    border-bottom: 4px solid #00d4ff !important;
    color: #ffffff !important;
}

/* ===== LOG FEED ===== */
.stExpander {
    background: rgba(255,255,255,0.02) !important;
    border: 1px solid rgba(255,255,255,0.05) !important;
}

/* ===== EXPANDER ===== */
.streamlit-expanderHeader {
    background: rgba(255,255,255,0.04) !important;
    border-radius: 12px !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
    padding: 10px !important;
}

/* ===== SIDEBAR ===== */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0e1117, #07090f) !important;
    border-right: 1px solid rgba(255,255,255,0.08);
    min-width: 220px !important;
    max-width: 250px !important;
}

/* Sidebar items hover */
section[data-testid="stSidebar"] .css-1d391kg:hover {
    background: rgba(255,255,255,0.05);
    border-radius: 8px;
}

/* ===== INPUT FIELDS ===== */
.stTextInput input {
    background: rgba(255,255,255,0.05) !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 10px !important;
    color: white !important;
    padding: 10px !important;
}

/* Focus effect */
.stTextInput input:focus {
    border: 1px solid #00d4ff !important;
    box-shadow: 0 0 10px rgba(0,212,255,0.4);
}

/* ===== BUTTONS ===== */
.stButton button {
    background: linear-gradient(135deg, #00d4ff, #7f5af0);
    color: white;
    border-radius: 10px;
    border: none;
    padding: 8px; /* Reduced padding prevents text wrap in narrow columns */
    font-weight: 600;
    transition: all 0.3s ease;
}

/* Button hover */
.stButton button:hover {
    transform: scale(1.05);
    box-shadow: 0 0 15px rgba(127,90,240,0.6);
}

/* ===== SCROLLBAR ===== */
::-webkit-scrollbar {
    width: 8px;
}
::-webkit-scrollbar-thumb {
    background: linear-gradient(#00d4ff, #7f5af0);
    border-radius: 10px;
}

</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# HELPERS (HARDENED)
# ─────────────────────────────────────────────

def api_get(path):
    try:
        url = f"{CORE_API}{path}"
        r = requests.get(
            url,
            timeout=5,
            headers={"Host": "localhost:5001"}
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
            headers={"Host": "localhost:5001"}
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

def verify_integrity(events):
    """Verifies the SHA-256 chain of the last 20 events."""
    if not events: return True, "GENESIS"
    subset = events[-50:] # Check up to last 50 for better accuracy
    for i in range(1, len(subset)):
        curr = subset[i]
        prev = subset[i-1]
        if "previous_hash" in curr and "hash" in prev:
            if curr["previous_hash"] != prev["hash"]:
                return False, f"Gap at index {len(events)-len(subset)+i}"
    return True, "VERIFIED"

def parse_time(ts):
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except:
        return None

# ---------------- SIDEBAR ----------------

with st.sidebar:
    st.markdown("<h1 style='text-align: center; font-size: 3rem; margin-bottom: 0;'>🛡️</h1>", unsafe_allow_html=True)
    st.title("SOC Control")
    st.divider()

    core_status = api_get("/control/http/status")
    docker_ok = core_status.get("docker_available", False) if core_status else False
    
    if core_status:
        st.success("API CONNECTED")
        if docker_ok:
            st.success("DOCKER AVAILABLE")
        else:
            st.error("DOCKER UNAVAILABLE")
    else:
        st.error("API UNREACHABLE")

    st.subheader("📡 Core Pulse")
    core_status = api_get("/control/http/status")
    if core_status:
        st.success("API CONNECTED")
    else:
        st.error("API UNREACHABLE")

    st.divider()
    st.subheader("⚡ Traps Status")
    
    # Clean UI for Service Toggles
    def service_toggle(name, path, is_running):
        col1, col2 = st.columns([3, 1], vertical_alignment="center")
        col1.write(f"**{name}**")
        if is_running:
            if col2.button("OFF", key=f"stop_{name.lower()}", use_container_width=True):
                api_post(f"/control/{path}/stop"); st.rerun()
        else:
            if col2.button("ON", key=f"start_{name.lower()}", use_container_width=True):
                api_post(f"/control/{path}/start"); st.rerun()

    http_running = core_status.get("running", False) if core_status else False
    service_toggle("HTTP/Web", "http", http_running)
    
    ssh_running = api_get("/control/ssh/status").get("running", False)
    service_toggle("SSH/Console", "ssh", ssh_running)

    st.divider()
    if st.button("🧹 Clear Forensic History"):
        if LOG_FILE.exists():
            LOG_FILE.unlink()
            # Also clear the chain reference in the core if possible (future)
        st.rerun()

    st.divider()
    refresh_rate = st.select_slider("Refresh (sec)", options=[1, 2, 3, 5, 10], value=3)


# ---------------- MAIN DASHBOARD ----------------

# Header with Integrity Badge
top_col1, gap_col, top_col2 = st.columns([6, 1.5, 2.5], vertical_alignment="bottom")
with top_col1:
    st.title("🛡️ Threat Control Center")
with top_col2:
    events = load_events()
    valid, msg = verify_integrity(events)
    if valid:
        st.success(f"🔒 **CHAIN:** {msg}")
    else:
        st.error(f"⚠️ **CHAIN:** {msg}")

# Main Tabs for SOC Layout
tab1, tab2, tab3 = st.tabs(["📊 Live Surveillance", "🕵️ Attacker Intel", "📜 Forensic Feed"])

while True:
    events = load_events()
    df = pd.DataFrame(events)
    
    # --- Tab 1: Live Surveillance ---
    with tab1:
        # High-Impact Metrics
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Telemetry Volume", len(events), delta="Total Events")
        
        malicious_count = len(df[df['behaviour'] == 'MALICIOUS']) if not df.empty else 0
        m2.metric("Threat Alerts", malicious_count, delta=f"{malicious_count} active", delta_color="inverse")
        
        confirmed_count = len(df[df['behaviour'] == 'CONFIRMED_ATTACK']) if not df.empty else 0
        m3.metric("Lateral Moves", confirmed_count, delta=f"{confirmed_count} persistent", delta_color="inverse")
        
        risk_avg = df['risk_score'].mean() if not df.empty else 0.0
        m4.metric("Risk Index", f"{risk_avg:.1f}", delta="Average Risk")

        conf_avg = df['confidence'].mean() * 100 if not df.empty else 0.0
        m5.metric("Detection Trust", f"{conf_avg:.1f}%", delta="Model Accuracy")

        st.write("") # Spacer

        # Charts Row
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("📈 Interaction Velocity")
            if not df.empty:
                df['dt'] = pd.to_datetime(df['timestamp'])
                df_trend = df.resample('1min', on='dt').size().rename("inter")
                st.area_chart(df_trend, height=250, use_container_width=True)
            else:
                st.info("Awaiting telemetry...")

        with c2:
            st.subheader("📊 Classified Behaviours")
            if not df.empty:
                counts = df['behaviour'].value_counts()
                # Horizontal bar chart prevents label overlap
                st.bar_chart(counts, height=250, use_container_width=True, horizontal=True)
            else:
                st.info("Awaiting behavior patterns...")

    # --- Tab 2: Attacker Intel ---
    with tab2:
        st.subheader("🎯 High-Risk Attacker Profile Mapping")
        if not df.empty:
            def extract_ip(row):
                details = row.get('details')
                if isinstance(details, dict):
                    return details.get('client_ip') or row.get('client_ip', 'UNKNOWN')
                return row.get('client_ip', 'UNKNOWN')
            
            df['ip'] = df.apply(extract_ip, axis=1)
            ip_stats = df.groupby('ip').agg({
                'behaviour': lambda x: x.iloc[-1],
                'risk_score': 'max',
                'event_type': 'count'
            }).sort_values('risk_score', ascending=False)
            
            ip_stats.columns = ["Current Status", "Peak Risk", "Hits"]
            st.dataframe(ip_stats, use_container_width=True)
        else:
            st.info("No malicious profiles identified yet.")

    # --- Tab 3: Forensic Feed ---
    with tab3:
        st.subheader("📟 Real-Time Audit Log")
        if events:
            for event in reversed(events[-20:]):
                # Extraction
                b = event.get('behaviour', 'NEW')
                rs = event.get('risk_score', 0.0)
                conf = event.get('confidence', 0.0)
                model = event.get('ml_model', 'N/A')
                fast = event.get('fast_path', False)
                
                # Indicator 
                color = "🔴" if b in ("MALICIOUS", "CONFIRMED_ATTACK", "KILL_CHAIN_CONFIRMED") else \
                        "🟡" if b == "SUSPICIOUS" else "🟢"
                
                # Risk Badge
                risk_lvl = "LOW" if rs < 4 else "MEDIUM" if rs < 10 else "HIGH" if rs < 15 else "CRITICAL"
                
                with st.expander(f"{color} {event.get('event_type')} | {event.get('details', {}).get('client_ip', 'UNK')} | RISK: {rs} ({risk_lvl})"):
                    # ML Meta-data
                    c1, c2, c3 = st.columns(3)
                    c1.markdown(f"**Model:** `{model}`")
                    c2.markdown(f"**Confidence:** `{conf:.2%}`")
                    c3.markdown(f"**Path:** `{'Fast-Track' if fast else 'Deep-Analysis'}`")
                    
                    st.divider()
                    
                    # Risk Context
                    reasons = event.get('state_transition', {}).get('reasons', [])
                    if reasons:
                        st.markdown(f"**Trigger Context:** {', '.join(reasons)}")
                    
                    st.json(event)
        else:
            st.info("Audit log empty. Deploy traps to begin ingestion.")

    # This dummy container approach handles the refresh
    time.sleep(refresh_rate)
    st.rerun()