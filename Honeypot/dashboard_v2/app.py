import streamlit as st
import pandas as pd
import time
from api_client import api_get
from log_parser import load_events
import components as comp

st.set_page_config(page_title="SOC Dashboard v2", layout="wide")

# Minimal, professional CSS structure
st.markdown("""
<style>
    /* Dark professional theme */
    .stApp {
        background-color: #0e1117;
        color: #c9d1d9;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    .metric-container {
        background-color: #161b22;
        border-top: 2px solid #58a6ff;
        border-radius: 4px;
        padding: 15px;
        margin-bottom: 10px;
    }
    
    h1, h2, h3 {
        color: #ffffff;
        font-weight: 400;
    }
    
    /* Plain buttons */
    .stButton>button {
        background-color: #21262d;
        color: #c9d1d9;
        border: 1px solid #30363d;
        border-radius: 4px;
    }
    .stButton>button:hover {
        background-color: #30363d;
        border-color: #8b949e;
    }
</style>
""", unsafe_allow_html=True)

# Main Application
st.title("HONEYPOT SOC DASHBOARD")
st.markdown("---")

# Data fetching
events = load_events()
df = pd.DataFrame(events)

sys_status = api_get("/control/status")
core_ok = bool(sys_status)

http_status = api_get("/control/http/status")
ssh_status = api_get("/control/ssh/status")
current_tier = sys_status.get("ai_mode", 3) if core_ok else 3

# Top Row Metrics
st.subheader("LIVE TELEMETRY")
mcol1, mcol2, mcol3, mcol4 = st.columns(4)

total_events = len(events)
malicious = len(df[df["behaviour"] == "MALICIOUS"]) if not df.empty and "behaviour" in df.columns else 0
confirmed = len(df[df["behaviour"] == "CONFIRMED_ATTACK"]) if not df.empty and "behaviour" in df.columns else 0

containments = 0
if not df.empty and "response" in df.columns:
    containments = df["response"].apply(lambda r: isinstance(r, dict) and r.get("action") == "CONTAIN").sum()

mcol1.metric("Total Events", total_events)
mcol2.metric("Malicious Signatures", malicious)
mcol3.metric("Confirmed Attacks", confirmed)
mcol4.metric("Active Containments", containments)

st.markdown("---")

# Layout
col_left, col_right = st.columns([1, 2])

with col_left:
    comp.render_system_status(core_ok, sys_status)
    st.markdown("---")
    comp.render_controls(core_ok, http_status.get("running", False), ssh_status.get("running", False), current_tier)

with col_right:
    # ── Live Attack Narrative ──
    st.subheader("LIVE ATTACK NARRATIVE")
    if not df.empty:
        # Find the most recent confirmed or malicious attack
        df_attacks = df[df["behaviour"].isin(["MALICIOUS", "CONFIRMED_ATTACK", "KILL_CHAIN_CONFIRMED"])]
        if not df_attacks.empty:
            last_attack = df_attacks.iloc[-1]
            details = last_attack.get("details", {}) or {}
            ip = details.get("client_ip", "UNKNOWN")
            
            st.markdown(f"**Target Tracker (IP):** `{ip}`")
            st.markdown(f"**Attack Phase:** `{last_attack.get('behaviour', 'UNKNOWN')}`")
            st.markdown(f"**Assessed Risk:** `{last_attack.get('risk_score', 0.0)}`")
            
            payload = details.get("command") or details.get("payload", "")
            if payload:
                st.markdown("**Last Identified Action:**")
                st.code(payload)
        else:
            st.info("No active threat trajectories detected.")
    else:
        st.info("Awaiting telemetry...")
        
    st.markdown("---")
    comp.render_containments(events)

st.markdown("---")
comp.render_threat_intel(df)

st.markdown("---")
st.subheader("RAW EVENTS LOG (Filtered)")
if not df.empty:
    st.dataframe(df.tail(50).iloc[::-1], use_container_width=True)
    
    # Add Export to CSV functionality
    csv_data = df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 Download Full Logs as CSV",
        data=csv_data,
        file_name='honeypot_events_log.csv',
        mime='text/csv',
    )
else:
    st.info("Event log is empty.")

st.markdown("---")
st.subheader("NETWORK TUNNELS")
tunnels = api_get("/control/tunnels")
if tunnels:
    tcol1, tcol2, tcol3 = st.columns(3)
    tcol1.markdown(f"**Dashboard:** `{tunnels.get('dashboard', 'Pending')}`")
    tcol2.markdown(f"**HTTP Trap:** `{tunnels.get('http_trap', 'Pending')}`")
    ssh_t = tunnels.get('ssh_trap') or 'Pending'
    if ssh_t != 'Pending':
        if ":" in ssh_t:
            host, port = ssh_t.rsplit(":", 1)
            # Remove any lingering protocol prefix just in case
            host = host.split("://")[-1]
            tcol3.markdown(f"**SSH Trap:** `ssh -p {port} root@{host}`")
        else:
            host = ssh_t.split("://")[-1]
            tcol3.markdown(f"**SSH Trap:** `ssh root@{host}`")
    else:
        tcol3.markdown(f"**SSH Trap:** `Pending`")
else:
    st.warning("Tunnels not running or core unreachable.")

# Auto-refresh
time.sleep(3)
st.rerun()
