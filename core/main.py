# core/main.py

from flask import Flask, request
from datetime import datetime, timezone

from core.orchestrator import Orchestrator
from forensics.logger import CentralLogger
from behaviour.behaviour_classifier import BehaviourClassifier

app = Flask(__name__)

orchestrator = Orchestrator()
logger = CentralLogger()
classifier = BehaviourClassifier()

# ---------------- EVENT INGEST ----------------

@app.route("/event", methods=["POST"])
def receive_event():
    event = request.get_json(force=True)

    if not event or "event_type" not in event:
        return {"error": "invalid event"}, 400

    result = classifier.process_event(event)

    # FULL ENRICHMENT
    enriched = {
        **event,
        "behaviour": result.get("behaviour", "UNKNOWN"),
        "attack_type": result.get("attack_type", "UNKNOWN"),
        "confidence": result.get("confidence", 0.0),
        "risk_score": result.get("risk_score", 0.0),
        "response": result.get("response", {}),
        "state_transition": result.get("state_transition", {}),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    logger.log(enriched)

    # Return enriched so services (HTTP/SSH) can adapt
    return enriched, 200


# ---------------- HTTP CONTROLS ----------------

@app.route("/control/http/start", methods=["POST"])
def start_http():
    orchestrator.start_http()
    return {"started": True}, 200


@app.route("/control/http/stop", methods=["POST"])
def stop_http():
    orchestrator.stop_http()
    return {"stopped": True}, 200


@app.route("/control/http/status", methods=["GET"])
def http_status():
    return {"running": orchestrator.http_running()}, 200


# ---------------- SSH CONTROLS ----------------

@app.route("/control/ssh/start", methods=["POST"])
def start_ssh():
    orchestrator.start_ssh()
    return {"started": True}, 200


@app.route("/control/ssh/stop", methods=["POST"])
def stop_ssh():
    orchestrator.stop_ssh()
    return {"stopped": True}, 200


@app.route("/control/ssh/status", methods=["GET"])
def ssh_status():
    return {"running": orchestrator.ssh_running()}, 200


# ---------------- MAIN ----------------

if __name__ == "__main__":
    print("[CORE] Behaviour-Aware Honeypot starting...")
    app.run(host="0.0.0.0", port=5001)