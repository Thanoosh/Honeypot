"""
Health check for Behaviour-Aware Honeypot
Run from project root: python test_health.py
Skips dashboard (Streamlit) and heavy ML model loading.
"""
import sys

results = []

def check(label, fn):
    try:
        fn()
        results.append(("PASS", label, ""))
    except Exception as e:
        results.append(("FAIL", label, str(e)))

# ── Module imports ─────────────────────────────
check("core.orchestrator",  lambda: __import__("core.orchestrator",  fromlist=["Orchestrator"]))
check("core.event_bus",     lambda: __import__("core.event_bus",     fromlist=["EventBus"]))
check("core.config",        lambda: __import__("core.config"))
check("forensics.logger",   lambda: __import__("forensics.logger",   fromlist=["CentralLogger"]))
check("behaviour.behaviour_classifier", lambda: __import__("behaviour.behaviour_classifier", fromlist=["BehaviourClassifier"]))
check("behaviour.feature_extractor",    lambda: __import__("behaviour.feature_extractor",    fromlist=["FeatureExtractor"]))
check("behaviour.rule_engine",          lambda: __import__("behaviour.rule_engine",          fromlist=["RuleEngine"]))
check("behaviour.response_engine",      lambda: __import__("behaviour.response_engine",      fromlist=["ResponseEngine"]))
check("behaviour.adaptation_engine",    lambda: __import__("behaviour.adaptation_engine"))

# ── Flask app creation ─────────────────────────
def check_flask_app():
    from core.main import app
    assert app is not None, "Flask app is None"
check("core.main — Flask app init", check_flask_app)

# ── BehaviourClassifier: SSH login attempt ─────
def check_classifier_ssh():
    from behaviour.behaviour_classifier import BehaviourClassifier
    clf = BehaviourClassifier()
    result = clf.process_event({
        "event_type": "ssh_login_attempt",
        "source_ip": "127.0.0.1",
        "username": "root",
        "password": "admin",
        "session_id": "test-001"
    })
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "behaviour" in result, f"Missing 'behaviour'. Keys: {list(result.keys())}"
check("BehaviourClassifier — ssh_login_attempt", check_classifier_ssh)

# ── BehaviourClassifier: HTTP SQL injection ────
def check_classifier_http():
    from behaviour.behaviour_classifier import BehaviourClassifier
    clf = BehaviourClassifier()
    result = clf.process_event({
        "event_type": "http_request",
        "source_ip": "10.0.0.1",
        "path": "/admin' OR 1=1--",
        "method": "GET",
        "session_id": "test-002"
    })
    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert "behaviour" in result, f"Missing 'behaviour'. Keys: {list(result.keys())}"
check("BehaviourClassifier — http_request (SQLi)", check_classifier_http)

# ── CentralLogger smoke test ───────────────────
def check_logger():
    from forensics.logger import CentralLogger
    log = CentralLogger()
    log.log({"event_type": "test", "source_ip": "127.0.0.1", "session_id": "test-000"})
check("CentralLogger — log()", check_logger)

# ── EventBus smoke test ────────────────────────
def check_event_bus():
    from core.event_bus import EventBus
    bus = EventBus()
    received = []
    bus.subscribe("test_event", lambda e: received.append(e))
    bus.publish("test_event", {"data": "hello"})
    assert len(received) == 1, f"Expected 1 event, got {len(received)}"
check("EventBus — subscribe & publish", check_event_bus)

# ── Print results ──────────────────────────────
print()
print("=" * 58)
print("   BEHAVIOUR-AWARE HONEYPOT — HEALTH CHECK")
print("=" * 58)
passed = failed = 0
for status, label, err in results:
    if status == "PASS":
        print(f"  ✓  {label}")
        passed += 1
    else:
        print(f"  ✗  {label}")
        print(f"     └─ {err}")
        failed += 1

print("=" * 58)
print(f"  {passed} passed  |  {failed} failed  |  {passed+failed} total")
print("=" * 58)
sys.exit(0 if failed == 0 else 1)
