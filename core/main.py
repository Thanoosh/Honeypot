from flask import Flask, request
from datetime import datetime, UTC

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

    # ✅ FULL ENRICHMENT (THIS WAS MISSING)
    enriched = {
        **event,
        "behaviour": result.get("behaviour", "UNKNOWN"),
        "attack_type": result.get("attack_type", "UNKNOWN"),
        "confidence": result.get("confidence", 0.0),
        "risk_score": result.get("risk_score", 0.0),
        "response": result.get("response", {}),
        "state_transition": result.get("state_transition", {}),
        "timestamp": datetime.now(UTC).isoformat(),
    }

    logger.log(enriched)

    # 🔑 Return enriched so services (HTTP/SSH) can adapt
    return enriched, 200


# ---------------- CONTROLS ----------------

@app.route("/control/http/start", methods=["POST"])
def start_http():
    orchestrator.start_http()
    return {"started": True}, 200


@app.route("/control/ssh/start", methods=["POST"])
def start_ssh():
    orchestrator.start_ssh()
    return {"started": True}, 200


@app.route("/control/http/status", methods=["GET"])
def http_status():
    return {"running": orchestrator.http_running()}, 200


@app.route("/control/ssh/status", methods=["GET"])
def ssh_status():
    return {"running": orchestrator.ssh_running()}, 200


# ---------------- MAIN ----------------

if __name__ == "__main__":
    print("[CORE] Behaviour-Aware Honeypot starting...")
    app.run(host="0.0.0.0", port=5001)
print("STEP 1: main.py loaded")

from flask import Flask, request
print("STEP 2: flask imported")

from core.orchestrator import Orchestrator
print("STEP 3: orchestrator imported")

from forensics.logger import CentralLogger
print("STEP 4: logger imported")

from behaviour.behaviour_classifier import BehaviourClassifier
print("STEP 5: classifier imported")

app = Flask(__name__)
print("STEP 6: flask app created")

print("STEP 7: creating logger")
logger = CentralLogger()

print("STEP 8: creating classifier")
classifier = BehaviourClassifier()

print("STEP 9: creating orchestrator")
orchestrator = Orchestrator()

print("STEP 10: orchestrator created")
