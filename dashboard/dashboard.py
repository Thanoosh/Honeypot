import os
import streamlit as st
import pandas as pd
import json
import time
import requests
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
LOG_FILE = Path("data/logs/events.log")

CORE_API = os.environ.get("CORE_API", "http://honeypot_core:5001")

st.set_page_config(
    page_title="Honeypot SOC — AI Control",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────
# PREMIUM CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&family=JetBrains+Mono:wght@400;600&display=swap');

.stApp {
    background: radial-gradient(ellipse at top left, #0a0e1a 0%, #05070d 60%, #010204 100%);
    color: #e6edf3;
    font-family: 'Inter', sans-serif;
}

/* ===== METRIC CARDS ===== */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.01) 100%) !important;
    padding: 22px !important;
    border-radius: 16px !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    backdrop-filter: blur(20px) !important;
    transition: all 0.35s cubic-bezier(0.175, 0.885, 0.32, 1.275) !important;
    position: relative;
    overflow: hidden;
    box-shadow: 0 8px 40px rgba(0,0,0,0.5);
}
[data-testid="stMetric"]:hover {
    transform: translateY(-6px);
    border: 1px solid rgba(0,212,255,0.5) !important;
    box-shadow: 0 0 40px rgba(0,212,255,0.15), 0 12px 40px rgba(0,0,0,0.5);
}
[data-testid="stMetric"]::before {
    content: "";
    position: absolute;
    top: 0; left: 0;
    height: 3px; width: 100%;
    background: linear-gradient(90deg, #00d4ff, #7f5af0, #ff4b4b);
}
div[data-testid="stMetricValue"] {
    font-size: 2rem !important;
    font-weight: 900 !important;
    background: linear-gradient(135deg, #00d4ff, #7f5af0);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    letter-spacing: -1px;
}
div[data-testid="stMetricLabel"] {
    font-size: 0.75rem !important;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: #8892a0 !important;
    font-weight: 600 !important;
}

/* ===== AI MODE BADGE ===== */
.ai-badge {
    display: inline-block;
    padding: 6px 16px;
    border-radius: 30px;
    font-weight: 700;
    font-size: 0.8rem;
    letter-spacing: 1px;
    text-transform: uppercase;
}
.ai-badge-1 { background: rgba(100,100,120,0.3); border: 1px solid #555; color: #aaa; }
.ai-badge-2 { background: rgba(127,90,240,0.2); border: 1px solid #7f5af0; color: #a78bfa; }
.ai-badge-3 { background: rgba(0,212,255,0.15); border: 1px solid #00d4ff; color: #00d4ff; }

/* ===== CONTAINMENT ALERT ===== */
.containment-block {
    background: linear-gradient(135deg, rgba(255,75,75,0.12), rgba(127,90,240,0.08));
    border: 1px solid rgba(255,75,75,0.4);
    border-radius: 12px;
    padding: 16px 20px;
    margin: 10px 0;
    font-family: 'JetBrains Mono', monospace;
}
.containment-header {
    color: #ff4b4b;
    font-weight: 700;
    font-size: 0.85rem;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-bottom: 8px;
}
.terminal-output {
    background: #0d0f14;
    border: 1px solid rgba(0,212,255,0.2);
    border-radius: 8px;
    padding: 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    color: #7aff7a;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 220px;
    overflow-y: auto;
    line-height: 1.6;
}

/* ===== TABS ===== */
.stTabs [data-baseweb="tab-list"] {
    gap: 30px;
    border-bottom: 2px solid rgba(255,255,255,0.05);
    margin-bottom: 25px;
}
.stTabs [data-baseweb="tab"] {
    height: 54px;
    color: #8892a0;
    font-size: 16px;
    font-weight: 500;
    transition: all 0.3s ease;
}
.stTabs [aria-selected="true"] {
    border-bottom: 3px solid #00d4ff !important;
    color: #ffffff !important;
}

/* ===== SIDEBAR ===== */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0b0d14, #06080f) !important;
    border-right: 1px solid rgba(255,255,255,0.06);
    min-width: 260px !important;
    max-width: 280px !important;
}

/* ===== BUTTONS ===== */
.stButton button {
    background: linear-gradient(135deg, #00d4ff, #7f5af0);
    color: white;
    border-radius: 10px;
    border: none;
    padding: 8px 16px;
    font-weight: 600;
    transition: all 0.3s ease;
}
.stButton button:hover {
    transform: scale(1.04);
    box-shadow: 0 0 20px rgba(127,90,240,0.5);
}

/* ===== SELECT BOXES ===== */
.stSelectbox > div > div {
    background: rgba(255,255,255,0.05) !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 10px !important;
    color: white !important;
}

/* ===== EXPANDER ===== */
.stExpander {
    background: rgba(255,255,255,0.02) !important;
    border: 1px solid rgba(255,255,255,0.05) !important;
    border-radius: 10px !important;
}

/* ===== SCROLLBAR ===== */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-thumb {
    background: linear-gradient(#00d4ff, #7f5af0);
    border-radius: 10px;
}

/* ===== DIVIDER ===== */
hr { border: none; border-top: 1px solid rgba(255,255,255,0.06) !important; margin: 16px 0; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# API HELPERS
# ─────────────────────────────────────────────
def api_get(path, timeout=5):
    try:
        r = requests.get(f"{CORE_API}{path}", timeout=timeout,
                         headers={"Host": "localhost:5001"})
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        pass
    return {}


def api_post(path, body=None, timeout=5):
    try:
        r = requests.post(f"{CORE_API}{path}", json=body, timeout=timeout,
                          headers={"Host": "localhost:5001"})
        return r.status_code == 200
    except Exception:
        return False


from collections import deque

def load_events(max_events=1000):
    if not LOG_FILE.exists():
        return []
    events = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = deque(f, maxlen=max_events)
        
    for line in lines:
        try:
            events.append(json.loads(line))
        except Exception:
            pass
    return events


def verify_integrity(events):
    if not events:
        return True, "GENESIS"
    subset = events[-50:]
    for i in range(1, len(subset)):
        curr, prev = subset[i], subset[i - 1]
        if "previous_hash" in curr and "hash" in prev:
            if curr["previous_hash"] != prev["hash"]:
                return False, f"Gap at index {len(events)-len(subset)+i}"
    return True, "VERIFIED"


def parse_time(ts):
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("<h1 style='text-align:center;font-size:2.8rem;margin-bottom:0'>🛡️</h1>",
                unsafe_allow_html=True)
    st.markdown("<p style='text-align:center;color:#8892a0;font-size:0.75rem;letter-spacing:3px;margin-top:0'>HONEYPOT SOC</p>",
                unsafe_allow_html=True)

    # ── Core health ──────────────────────────
    sys_status = api_get("/control/status")
    core_ok = bool(sys_status)

    st.divider()
    st.markdown("#### 🔌 System Health")

    if core_ok:
        st.success("API CONNECTED")
        llm_ok = sys_status.get("llm_available", False)
        llm_warm = sys_status.get("llm_warm", False)
        docker_ok = sys_status.get("docker_available", False)

        if llm_ok and llm_warm:
            st.success("🤖 LLM HOT & READY")
        elif llm_ok:
            st.warning("🤖 LLM LOADING (warming up...)")
        else:
            st.error("🤖 LLM OFFLINE (Eco fallback)")

        if docker_ok:
            st.success("🐳 DOCKER AVAILABLE")
        else:
            st.warning("🐳 DOCKER UNAVAILABLE")
    else:
        st.error("API UNREACHABLE")
        llm_ok = False
        docker_ok = False

    # ── AI Tier Selector ────────────────────
    st.divider()
    st.markdown("#### 🧠 AI Intelligence Tier")

    _tier_labels = {
        1: "🌿 Tier 1 — Eco (Rule-Based)",
        2: "⚡ Tier 2 — Standard (ML)",
        3: "🔥 Tier 3 — Advanced (LLM)",
    }

    current_mode = sys_status.get("ai_mode", 3) if core_ok else 3
    current_label = _tier_labels.get(current_mode, "Tier 3")

    selected_label = st.selectbox(
        "Select AI Mode",
        options=list(_tier_labels.values()),
        index=current_mode - 1,
        key="ai_mode_select",
        label_visibility="collapsed",
    )
    selected_tier = [k for k, v in _tier_labels.items() if v == selected_label][0]

    if selected_tier != current_mode:
        if api_post("/control/ai_mode", {"mode": selected_tier}):
            st.success(f"Mode set to Tier {selected_tier}")
            st.rerun()
        else:
            st.error("Failed to set AI mode")

    # Tier description
    _tier_desc = {
        1: "Rule-based keyword detection. Static deception payloads. Lowest resource usage.",
        2: "Scikit-Learn fast classifier + async BiLSTM profiling. No LLM.",
        3: "Full pipeline: ML + BiLSTM + Phi-3 LLM for hyper-realistic AI deception.",
    }
    st.caption(_tier_desc.get(selected_tier, ""))

    # ── Trap Controls ────────────────────────
    st.divider()
    st.markdown("#### ⚡ Trap Controls")

    http_status = api_get("/control/http/status")
    ssh_status  = api_get("/control/ssh/status")
    http_running = http_status.get("running", False)
    ssh_running  = ssh_status.get("running", False)

    def service_toggle(name, path, is_running):
        col1, col2 = st.columns([3, 1], vertical_alignment="center")
        col1.write(f"**{name}**")
        if is_running:
            if col2.button("OFF", key=f"stop_{name}", use_container_width=True):
                api_post(f"/control/{path}/stop")
                st.rerun()
        else:
            if col2.button("ON", key=f"start_{name}", use_container_width=True):
                api_post(f"/control/{path}/start")
                st.rerun()

    service_toggle("HTTP/Web Trap", "http", http_running)
    service_toggle("SSH/Console Trap", "ssh", ssh_running)

    st.divider()
    if st.button("🧹 Clear Forensic Logs"):
        if LOG_FILE.exists():
            LOG_FILE.unlink()
        st.rerun()

    st.divider()
    refresh_rate = st.select_slider("🔄 Refresh (sec)", options=[1, 2, 3, 5, 10], value=3)


# ─────────────────────────────────────────────
# MAIN HEADER
# ─────────────────────────────────────────────
hcol1, hcol2, hcol3 = st.columns([5, 2, 2], vertical_alignment="bottom")
with hcol1:
    st.title("🛡️ Threat Control Center")
    mode_label = sys_status.get("ai_mode_label", "Advanced (LLM)") if core_ok else "—"
    tier_num = sys_status.get("ai_mode", 3) if core_ok else 3
    st.markdown(
        f"<span class='ai-badge ai-badge-{tier_num}'>AI: {mode_label}</span>",
        unsafe_allow_html=True
    )

with hcol3:
    events = load_events()
    valid, msg = verify_integrity(events)
    if valid:
        st.success(f"🔒 Chain: {msg}")
    else:
        st.error(f"⚠️ Chain: {msg}")


# ─────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Live Surveillance",
    "🔥 Containment Activity",
    "🕵️ Attacker Intel",
    "📜 Forensic Feed",
    "🌐 Connectivity",
])

while True:
    events = load_events()
    df = pd.DataFrame(events)

    # Normalise columns
    if not df.empty:
        for col in ["behaviour", "risk_score", "confidence", "event_type",
                    "client_ip", "ai_classification", "threat_level",
                    "terminal_output", "response"]:
            if col not in df.columns:
                df[col] = None

    # ── Tab 1: Live Surveillance ──────────────────────────────────────
    with tab1:
        m1, m2, m3, m4, m5, m6 = st.columns(6)
        m1.metric("Total Events", len(events))
        m2.metric("Malicious", len(df[df["behaviour"] == "MALICIOUS"]) if not df.empty else 0)
        m3.metric("Confirmed", len(df[df["behaviour"] == "CONFIRMED_ATTACK"]) if not df.empty else 0)
        m4.metric("Kill Chain", len(df[df["behaviour"] == "KILL_CHAIN_CONFIRMED"]) if not df.empty else 0)

        contain_count = 0
        if not df.empty and "response" in df.columns:
            contain_count = df["response"].apply(
                lambda r: isinstance(r, dict) and r.get("action") == "CONTAIN"
            ).sum()
        m5.metric("🔒 Contained", contain_count)

        risk_avg = df["risk_score"].mean() if not df.empty else 0.0
        m6.metric("Risk Index", f"{risk_avg:.1f}")

        st.write("")

        c1, c2, c3 = st.columns(3)

        with c1:
            st.subheader("📈 Event Velocity")
            if not df.empty and "timestamp" in df.columns:
                df["dt"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
                df_clean = df.dropna(subset=["dt"])
                if not df_clean.empty:
                    trend = df_clean.resample("1min", on="dt").size().rename("events")
                    st.area_chart(trend, height=240, use_container_width=True)
                else:
                    st.info("Awaiting telemetry...")
            else:
                st.info("Awaiting telemetry...")

        with c2:
            st.subheader("📊 Behaviour States")
            if not df.empty:
                counts = df["behaviour"].value_counts()
                st.bar_chart(counts, height=240, use_container_width=True, horizontal=True)
            else:
                st.info("No data yet")

        with c3:
            st.subheader("🤖 AI Sequence Profiles")
            if not df.empty and "ai_classification" in df.columns:
                valid_ai = df[~df["ai_classification"].isin(
                    ["UNKNOWN", "UNKNOWN (Needs Training)", "Eco-Mode (Rule-Based)", None, ""]
                )]
                if not valid_ai.empty:
                    ai_counts = valid_ai["ai_classification"].value_counts()
                    st.bar_chart(ai_counts, height=240, use_container_width=True, horizontal=True)
                else:
                    st.info("Awaiting deep sequence profiles...")
            else:
                st.info("Awaiting deep sequence profiles...")

        # ── Live LLM Engine Status Widget ──
        st.divider()
        st.markdown("#### 🧠 Live AI Engine Status")
        ec1, ec2, ec3, ec4 = st.columns(4)
        ec1.metric("AI Tier", f"Tier {sys_status.get('ai_mode', '—')}" if core_ok else "—")
        ec2.metric("LLM Status", "🟢 HOT" if sys_status.get("llm_warm") else
                   ("🟡 Loading" if sys_status.get("llm_available") else "🔴 Offline"))
        ec3.metric("Model", "phi3:mini" if sys_status.get("llm_available") else "Eco-Fallback")
        ec4.metric("Containments", contain_count)

    # ── Tab 2: Containment Activity ───────────────────────────────────
    with tab2:
        st.subheader("🔥 Active Deception & Containment Tracker")
        st.caption("Events where the AI classified the attacker as high-threat and triggered logical containment.")

        if not df.empty:
            contained_events = []
            for ev in reversed(events):
                resp = ev.get("response", {})
                if isinstance(resp, dict) and resp.get("action") == "CONTAIN":
                    contained_events.append(ev)

            if contained_events:
                st.markdown(
                    f"<div style='padding:10px 16px;background:rgba(255,75,75,0.1);"
                    f"border:1px solid rgba(255,75,75,0.4);border-radius:10px;margin-bottom:16px'>"
                    f"🚨 <b>{len(contained_events)}</b> attacker session(s) currently in AI deception containment.</div>",
                    unsafe_allow_html=True,
                )

                for ev in contained_events[:15]:
                    details = ev.get("details", {}) or {}
                    ip = details.get("client_ip") or ev.get("client_ip", "UNKNOWN")
                    behaviour = ev.get("behaviour", "UNKNOWN")
                    risk = ev.get("risk_score", 0.0)
                    ai_class = ev.get("ai_classification", "N/A")
                    ai_mode_used = ev.get("ai_mode", "N/A")
                    terminal_out = ev.get("terminal_output", "")
                    mitre = ev.get("mitre_technique_id", "")
                    ts = ev.get("timestamp", "")
                    cmd = details.get("command") or details.get("payload", "")
                    resp_notes = ev.get("response", {}).get("notes", "")

                    header = f"🔴 CONTAINED | {ip} | {behaviour} | Risk: {risk} | {ts[:19] if ts else ''}"

                    with st.expander(header, expanded=False):
                        cols = st.columns(4)
                        cols[0].markdown(f"**IP:** `{ip}`")
                        cols[1].markdown(f"**Behaviour:** `{behaviour}`")
                        cols[2].markdown(f"**AI Profile:** `{ai_class}`")
                        cols[3].markdown(f"**Risk Score:** `{risk}`")

                        if mitre:
                            st.markdown(f"**MITRE TTP:** `{mitre}` — {ev.get('mitre_technique_name', '')}")

                        if cmd:
                            st.markdown(f"**Attacker Command:**")
                            st.code(cmd, language="bash")

                        if resp_notes:
                            st.markdown(f"**Containment Reason:** _{resp_notes}_")

                        if terminal_out and terminal_out.strip():
                            st.markdown("**🤖 AI-Generated Deception Payload (shown to attacker):**")
                            st.markdown(
                                f"<div class='terminal-output'>{terminal_out}</div>",
                                unsafe_allow_html=True,
                            )
                        else:
                            tier = sys_status.get("ai_mode", 3) if core_ok else 3
                            if tier < 3:
                                st.info(f"Static payload used (Tier {tier} mode — upgrade to Tier 3 for LLM output)")
                            else:
                                st.warning("LLM payload not captured for this event.")
            else:
                st.info("No containment events yet. Begin an attack simulation to trigger containment.")
                st.markdown("""
**How to trigger containment:**
1. Ensure **Tier 3 (Advanced)** AI mode is selected in sidebar
2. Send multiple malicious requests to the HTTP or SSH honeypot
3. The system escalates: `NEW → PROBING → MALICIOUS → CONFIRMED_ATTACK → CONTAIN`
4. Once contained, the LLM generates hyper-realistic fake responses shown to the attacker
                """)
        else:
            st.info("Audit log empty. Deploy traps to begin monitoring.")

    # ── Tab 3: Attacker Intel ─────────────────────────────────────────
    with tab3:
        st.subheader("🎯 Attacker Profile Intelligence")
        if not df.empty:
            def extract_ip(row):
                details = row.get("details")
                if isinstance(details, dict):
                    return details.get("client_ip") or row.get("client_ip", "UNKNOWN")
                return row.get("client_ip", "UNKNOWN")

            df["ip"] = df.apply(extract_ip, axis=1)
            for col in ["ai_classification", "threat_level"]:
                if col not in df.columns:
                    df[col] = "UNKNOWN"

            # Build per-IP containment counts
            def count_contains(responses):
                return sum(1 for r in responses if isinstance(r, dict) and r.get("action") == "CONTAIN")

            ip_stats = df.groupby("ip").agg(
                Phase=("behaviour", lambda x: x.iloc[-1]),
                ML_Profile=("ai_classification", lambda x: x.iloc[-1]),
                Threat_Status=("threat_level", lambda x: x.iloc[-1]),
                Peak_Risk=("risk_score", "max"),
                Hits=("event_type", "count"),
                Contained=("response", count_contains),
            ).sort_values("Peak_Risk", ascending=False)

            st.dataframe(ip_stats, use_container_width=True)
        else:
            st.info("No profiles yet.")

    # ── Tab 4: Forensic Feed ──────────────────────────────────────────
    with tab4:
        st.subheader("📟 Real-Time Forensic Audit Log")
        if events:
            for ev in reversed(events[-25:]):
                b = ev.get("behaviour", "NEW")
                rs = ev.get("risk_score", 0.0)
                conf = ev.get("confidence", 0.0)
                model = ev.get("ml_model", "N/A")
                fast = ev.get("fast_path", False)
                details = ev.get("details", {}) or {}
                mitre_id = ev.get("mitre_technique_id", "")
                terminal_out = ev.get("terminal_output", "")
                response_action = ""
                if isinstance(ev.get("response"), dict):
                    response_action = ev["response"].get("action", "")

                color = "🔴" if b in ("MALICIOUS", "CONFIRMED_ATTACK", "KILL_CHAIN_CONFIRMED") else \
                        "🟠" if response_action == "CONTAIN" else \
                        "🟡" if b == "SUSPICIOUS" else "🟢"
                risk_lvl = "CRITICAL" if rs >= 15 else "HIGH" if rs >= 10 else "MEDIUM" if rs >= 4 else "LOW"
                mitre_badge = f"[{mitre_id}]" if mitre_id else ""
                action_badge = f" ▶ {response_action}" if response_action else ""
                header = (f"{color} {ev.get('event_type', 'EVENT')} {mitre_badge}{action_badge}"
                          f" | {details.get('client_ip', 'UNK')} | RISK: {rs} ({risk_lvl})")

                with st.expander(header):
                    c1, c2, c3, c4 = st.columns(4)
                    c1.markdown(f"**Model:** `{model}`")
                    c2.markdown(f"**Confidence:** `{conf:.2%}`")
                    c3.markdown(f"**Path:** `{'Fast' if fast else 'Deep'}`")
                    c4.markdown(f"**AI Profile:** `{ev.get('ai_classification', 'N/A')}`")

                    st.divider()

                    f1, f2, f3, f4 = st.columns(4)
                    f1.markdown(f"**Entropy:** `{details.get('entropy', 0.0):.2f}`")
                    f2.markdown(f"**Spec.Chars:** `{details.get('special_char_ratio', 0.0):.2%}`")
                    f3.markdown(f"**Traversals:** `{details.get('traversal_depth', 0)}`")
                    f4.markdown(f"**SQL/Shell:** `{details.get('sql_keyword_hits', 0)}/{details.get('shell_keyword_hits', 0)}`")

                    reasons = ev.get("state_transition", {}).get("reasons", [])
                    if reasons:
                        st.markdown(f"**Trigger:** {', '.join(reasons)}")

                    if response_action == "CONTAIN" and terminal_out and terminal_out.strip():
                        st.markdown("**🤖 LLM Deception Payload:**")
                        st.markdown(
                            f"<div class='terminal-output'>{terminal_out}</div>",
                            unsafe_allow_html=True,
                        )

                    st.json(ev)
        else:
            st.info("Audit log empty. Deploy traps to begin ingestion.")

    # ── Tab 5: Public Connectivity ────────────────────────────────────
    with tab5:
        st.subheader("🌐 Public Tunnel Endpoints")
        st.info("These tunnels securely expose your honeypot services to the internet.")

        if st.button("🔄 Refresh Tunnel Links"):
            st.rerun()

        tunnels = api_get("/control/tunnels")
        if tunnels:
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("### 🛡️ Dashboard")
                dash_url = tunnels.get("dashboard")
                st.code(dash_url or "Pending...")
            with c2:
                st.markdown("### 🕸️ HTTP Trap")
                http_url = tunnels.get("http_trap")
                st.code(http_url or "Pending...")
            with c3:
                st.markdown("### 🔑 SSH Trap")
                ssh_url = tunnels.get("ssh_trap")
                if ssh_url and ":" in ssh_url:
                    host, port = ssh_url.rsplit(":", 1)
                    st.code(f"ssh -p {port} root@{host}")
                else:
                    st.code(f"ssh root@{ssh_url}" if ssh_url else "Pending...")
        else:
            st.warning("Tunnels unavailable — ensure the core API is running.")

    time.sleep(refresh_rate)
    st.rerun()