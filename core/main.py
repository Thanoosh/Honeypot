# core/main.py

from flask import Flask, request, jsonify
from core.orchestrator import Orchestrator
from forensics.logger import CentralLogger
from behaviour.behaviour_classifier import BehaviourClassifier
from datetime import datetime, UTC

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

    ml = classifier.process_event(event)

    enriched = {
        **event,
        "behaviour": ml.get("behaviour", "UNKNOWN"),
        "attack_type": ml.get("attack_type", "UNKNOWN"),
        "confidence": ml.get("confidence", 0.0),
        "features": ml.get("features", {}),
        "timestamp": datetime.now(UTC).isoformat(),
    }

    logger.log(enriched)
    return {"status": "ok"}, 200


# ---------------- CONTROLS ----------------

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
