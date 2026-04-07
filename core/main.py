import os
os.environ["HF_HUB_DISABLE_FILE_LOCKS"] = "1"

import threading
import concurrent.futures
from flask import Flask, request, jsonify
from datetime import datetime, timezone
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
from core.orchestrator import Orchestrator
from core.alert_manager import AlertManager
from forensics.logger import CentralLogger
from behaviour.behaviour_classifier import BehaviourClassifier
from ml.attack_intent_classifier import AttackIntentClassifier
from behaviour.adaptation_engine import AdaptationEngine

# ✅ Configure logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)

# ✅ Create app
app = Flask(__name__)

# ✅ FIX: Disable host validation completely
# This ensures Docker requests like "honeypot_core:5001" are accepted
app.url_map.host_matching = False

# Optional proxy fix (safe for Docker)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)

logger = CentralLogger()
behaviour_classifier = BehaviourClassifier()
intent_classifier = AttackIntentClassifier()
alert_manager = AlertManager()
adaptation_engine = AdaptationEngine()

# ─────────────────────────────────────────────
# GLOBAL AI MODE STATE
# ─────────────────────────────────────────────
# Tier 1 = Eco (rule-based, static baits)
# Tier 2 = Standard (fast ML + BiLSTM, no LLM)
# Tier 3 = Advanced (full LLM Maneuvering Engine active)
_AI_MODE = 3
_AI_MODE_LOCK = threading.Lock()


def get_ai_mode() -> int:
    with _AI_MODE_LOCK:
        return _AI_MODE


def set_ai_mode(mode: int):
    global _AI_MODE
    with _AI_MODE_LOCK:
        _AI_MODE = mode
    # Propagate to the Maneuvering Engine immediately
    adaptation_engine.maneuver.ai_mode = mode
    # Propagate to classifiers
    behaviour_classifier.ai_mode = mode
    intent_classifier.ai_mode = mode
    print(f"[CORE] AI Mode switched to Tier {mode}")

# ─────────────────────────────────────────────
# ORCHESTRATOR
# ─────────────────────────────────────────────
try:
    from core.orchestrator import Orchestrator
    orchestrator = Orchestrator()
    ORCHESTRATOR_OK = True
    print("[CORE] Orchestrator ready — Docker control enabled")
except Exception as e:
    orchestrator = None
    ORCHESTRATOR_OK = False
    print(f"[CORE] WARNING: Orchestrator unavailable — {e}")

# ─────────────────────────────────────────────
# DEBUG (IMPORTANT)
# ─────────────────────────────────────────────
@app.before_request
def debug():
    print(f"[REQ] {request.method} {request.path} HOST={request.host}")

# ─────────────────────────────────────────────
# EVENT INGEST
# ─────────────────────────────────────────────
@app.route("/event", methods=["POST"])
def receive_event():
    event = request.get_json(silent=True)

    if not event or "event_type" not in event:
        return jsonify({"error": "invalid event"}), 400

    # ML ENRICHMENT (Stage 1 & 2)
    details = event.get("details", {})
    payload = details.get("payload", details.get("command", ""))
    
    # Run hybrid classifier if context is available
    ml_result = intent_classifier.classify(payload, context=details)
    
    # Merge ML insights into event
    event["attack_type"] = ml_result.get("attack_type", "BENIGN")
    event["confidence"] = ml_result.get("confidence", 0.0)
    event["ml_model"] = ml_result.get("model", "rule-engine")
    event["fast_path"] = ml_result.get("fast_path", True)

    result = behaviour_classifier.process_event(event)

    terminal_output = None
    response_action = result.get("response", {}).get("action")
    
    # If the attacker is contained, actively use LLM to hallucinate realistic terminal output
    if response_action == "CONTAIN":
        # 1. Trigger True Physical Sandboxing via Orchestrator asynchronously
        if ORCHESTRATOR_OK:
            client_ip = event.get("details", {}).get("client_ip") or event.get("client_ip", "UNKNOWN")
            if client_ip != "UNKNOWN":
                threading.Thread(target=orchestrator.contain_attacker, args=(client_ip,), daemon=True).start()

        # 2. Trigger the Adaptation Engine ONLY for SSH commands
        # The LLM call is wrapped in a 3-second hard deadline so the Flask
        # response is NEVER held longer than that regardless of LLM speed.
        # If the deadline fires, terminal_output is None and the SSH service
        # falls back to its local deterministic handler transparently.
        # The LLM future is NOT cancelled — it runs to completion in the
        # background so the LRU cache is populated for the next identical command.
        if payload and event.get("event_type", "").startswith("SSH"):
            behaviour_state = result.get("behaviour", "MALICIOUS")
            _ctx = {
                "cwd":             details.get("cwd", "/root"),
                "hostname":        details.get("hostname", "prod-web-01"),
                "username":        details.get("username", "root"),
                "available_files": details.get("available_files", []),
            }
            _llm_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            _future = _llm_pool.submit(
                adaptation_engine.apply, behaviour_state, payload, _ctx
            )
            _llm_pool.shutdown(wait=False)   # Don't block pool teardown
            try:
                terminal_output = _future.result(timeout=3.0)
            except concurrent.futures.TimeoutError:
                # LLM is still running in background — cache will benefit next call
                terminal_output = None
            except Exception as exc:
                logger.log({"event_type": "LLM_ERROR", "error": str(exc)})
                terminal_output = None

    enriched = {
        **event,
        "behaviour": result.get("behaviour", "UNKNOWN"),
        "attack_type": result.get("attack_type", "UNKNOWN"),
        "confidence": result.get("confidence", 0.0),
        "risk_score": result.get("risk_score", 0.0),
        "response": result.get("response", {}),
        "state_transition": result.get("state_transition", {}),
        "kill_chain": result.get("kill_chain", {}),
        "mitre_technique_id": result.get("mitre_technique_id"),
        "mitre_technique_name": result.get("mitre_technique_name"),
        "ai_classification": result.get("ai_classification"),
        "threat_level": result.get("threat_level"),
        "terminal_output": terminal_output,
        "ai_mode": get_ai_mode(),   # Record which tier was active for this event
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    logger.log(enriched)
    alert_manager.process(enriched)
    return jsonify(enriched), 200

# ─────────────────────────────────────────────
# HTTP CONTROLS
# ─────────────────────────────────────────────
@app.route("/control/http/start", methods=["POST"])
def start_http():
    if not ORCHESTRATOR_OK:
        return jsonify({"error": "Docker not available"}), 503
    try:
        orchestrator.start_http()
        return jsonify({"started": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/control/http/stop", methods=["POST"])
def stop_http():
    if not ORCHESTRATOR_OK:
        return jsonify({"error": "Docker not available"}), 503
    try:
        orchestrator.stop_http()
        return jsonify({"stopped": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/control/http/status", methods=["GET"])
def http_status():
    if not ORCHESTRATOR_OK:
        return jsonify({"running": False, "docker_available": False}), 200
    try:
        return jsonify({
            "running": orchestrator.http_running(),
            "docker_available": True,
        }), 200
    except Exception as e:
        return jsonify({"running": False, "docker_available": False, "error": str(e)}), 200

# ─────────────────────────────────────────────
# TUNNEL CONTROLS
# ─────────────────────────────────────────────
@app.route("/control/tunnels", methods=["GET"])
def get_tunnels():
    if not ORCHESTRATOR_OK:
        return jsonify({"error": "Docker not available"}), 503
    try:
        return jsonify(orchestrator.get_tunnels()), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─────────────────────────────────────────────
# SSH CONTROLS
# ─────────────────────────────────────────────
@app.route("/control/ssh/start", methods=["POST"])
def start_ssh():
    if not ORCHESTRATOR_OK:
        return jsonify({"error": "Docker not available"}), 503
    try:
        orchestrator.start_ssh()
        return jsonify({"started": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/control/ssh/stop", methods=["POST"])
def stop_ssh():
    if not ORCHESTRATOR_OK:
        return jsonify({"error": "Docker not available"}), 503
    try:
        orchestrator.stop_ssh()
        return jsonify({"stopped": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/control/ssh/status", methods=["GET"])
def ssh_status():
    if not ORCHESTRATOR_OK:
        return jsonify({"running": False, "docker_available": False}), 200
    try:
        return jsonify({
            "running": orchestrator.ssh_running(),
            "docker_available": True,
        }), 200
    except Exception as e:
        return jsonify({"running": False, "docker_available": False, "error": str(e)}), 200


# ─────────────────────────────────────────────
# AI MODE CONTROL
# ─────────────────────────────────────────────
@app.route("/control/ai_mode", methods=["GET"])
def get_ai_mode_endpoint():
    mode = get_ai_mode()
    labels = {1: "Eco (Rule-Based)", 2: "Standard (ML)", 3: "Advanced (LLM)"}
    return jsonify({"ai_mode": mode, "label": labels.get(mode, "Unknown")}), 200


@app.route("/control/ai_mode", methods=["POST"])
def set_ai_mode_endpoint():
    body = request.get_json(silent=True) or {}
    mode = body.get("mode")
    if mode not in (1, 2, 3):
        return jsonify({"error": "mode must be 1, 2, or 3"}), 400
    set_ai_mode(mode)
    return jsonify({"ai_mode": mode, "ok": True}), 200


@app.route("/control/status", methods=["GET"])
def system_status():
    """Comprehensive system status for the dashboard health panel."""
    try:
        engine_status = adaptation_engine.maneuver.status()
    except Exception:
        engine_status = {"error": "Maneuvering engine unavailable"}

    mode = get_ai_mode()
    labels = {1: "Eco (Rule-Based)", 2: "Standard (ML)", 3: "Advanced (LLM)"}

    return jsonify({
        "ai_mode": mode,
        "ai_mode_label": labels.get(mode, "Unknown"),
        "llm_available": engine_status.get("llm_available", False),
        "llm_warm": engine_status.get("llm_warm", False),
        "ollama_host": engine_status.get("ollama_host", "N/A"),
        "orchestrator_ok": ORCHESTRATOR_OK,
        "docker_available": ORCHESTRATOR_OK,
    }), 200


# ─────────────────────────────────────────────
# ENTRY
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("[CORE] Starting API on 5001...")
    app.run(host="0.0.0.0", port=5001, threaded=True, use_reloader=False)