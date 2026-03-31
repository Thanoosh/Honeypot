from flask import Flask, request, jsonify
from datetime import datetime, timezone
from werkzeug.middleware.proxy_fix import ProxyFix
from forensics.logger import CentralLogger
from behaviour.behaviour_classifier import BehaviourClassifier

# ✅ Create app
app = Flask(__name__)

# ✅ FIX: Disable host validation completely
# This ensures Docker requests like "honeypot_core:5001" are accepted
app.url_map.host_matching = False

# Optional proxy fix (safe for Docker)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)

logger = CentralLogger()
classifier = BehaviourClassifier()

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

    result = classifier.process_event(event)

    enriched = {
        **event,
        "behaviour": result.get("behaviour", "UNKNOWN"),
        "attack_type": result.get("attack_type", "UNKNOWN"),
        "confidence": result.get("confidence", 0.0),
        "risk_score": result.get("risk_score", 0.0),
        "response": result.get("response", {}),
        "state_transition": result.get("state_transition", {}),
        "kill_chain": result.get("kill_chain", {}),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    logger.log(enriched)
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
# ENTRY
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("[CORE] Starting API on 5001...")
    app.run(host="0.0.0.0", port=5001, threaded=True, use_reloader=False)