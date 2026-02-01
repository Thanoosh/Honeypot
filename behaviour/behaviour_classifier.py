import time
from collections import defaultdict
from typing import Dict, Any
from behaviour.response_engine import ResponseEngine


class BehaviourClassifier:
    NEW = "NEW"
    PROBING = "PROBING"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    CONFIRMED_ATTACK = "CONFIRMED_ATTACK"

    def __init__(self):
        self.attackers = defaultdict(self._init_attacker)
        self.response_engine = ResponseEngine()

    def _init_attacker(self):
        return {
            "state": self.NEW,
            "events": 0,
            "malicious_events": 0,
            "services": set(),
            "risk": 0.0,
            "first_seen": time.time(),
            "last_seen": time.time(),
        }

    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        ip = self._extract_ip(event)
        attacker = self.attackers[ip]

        attacker["events"] += 1
        attacker["last_seen"] = time.time()

        service = event.get("event_type", "").split("_")[0]
        attacker["services"].add(service)

        attack_type = event.get("attack_type", "BENIGN")
        confidence = float(event.get("confidence", 0.0))
        entropy = float(event.get("details", {}).get("entropy", 0.0))

        # ---------------- RISK SCORING ----------------
        if attack_type != "BENIGN":
            attacker["malicious_events"] += 1
            attacker["risk"] += 2

        attacker["risk"] += entropy
        attacker["risk"] += attacker["malicious_events"] * 1.5

        if len(attacker["services"]) > 1:
            attacker["risk"] += 2  # HTTP ↔ SSH pivot

        prev_state = attacker["state"]
        new_state, reasons = self._transition(attacker)
        attacker["state"] = new_state

        response = self.response_engine.decide(
            behaviour=new_state,
            attack_type=attack_type,
            confidence=confidence,
        )

        return {
            "behaviour": new_state,
            "attack_type": attack_type,
            "confidence": confidence,
            "risk_score": round(attacker["risk"], 2),
            "response": response,
            "state_transition": {
                "from": prev_state,
                "to": new_state,
                "reasons": reasons,
            },
        }

    # ---------------- STATE TRANSITION ----------------

    def _transition(self, attacker):
        reasons = []

        if attacker["events"] >= 2 and attacker["state"] == self.NEW:
            reasons.append("multiple interactions")
            return self.PROBING, reasons

        if attacker["malicious_events"] >= 1:
            reasons.append("malicious event detected")
            return self.SUSPICIOUS, reasons

        if attacker["malicious_events"] >= 3 or attacker["risk"] > 6:
            reasons.append("repeated malicious behaviour")
            return self.MALICIOUS, reasons

        if attacker["risk"] > 10 and attacker["events"] > 5:
            reasons.append("persistent high-risk attacker")
            return self.CONFIRMED_ATTACK, reasons

        return attacker["state"], ["no escalation"]

    def _extract_ip(self, event):
        return event.get("details", {}).get("client_ip") or "UNKNOWN"
