# behaviour/behaviour_classifier.py

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

    # FIX #7: KILL_CHAIN_CONFIRMED is now a proper class constant
    # so the dashboard, response engine, and all other modules
    # can reference BehaviourClassifier.KILL_CHAIN_CONFIRMED
    KILL_CHAIN_CONFIRMED = "KILL_CHAIN_CONFIRMED"

    # Priority order used for escalation comparisons
    STATE_PRIORITY = [NEW, PROBING, SUSPICIOUS, MALICIOUS, CONFIRMED_ATTACK, KILL_CHAIN_CONFIRMED]

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
            "accessed_env_file": False,
            "accessed_backup": False,
            "ssh_kill_chain": False,
        }

    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        ip = self._extract_ip(event)
        attacker = self.attackers[ip]

        attacker["events"] += 1
        attacker["last_seen"] = time.time()

        event_type = event.get("event_type", "")
        service = event_type.split("_")[0]
        attacker["services"].add(service)

        attack_type = event.get("attack_type", "BENIGN")
        confidence = float(event.get("confidence", 0.0))
        entropy = float(event.get("details", {}).get("entropy", 0.0))
        high_value = event.get("details", {}).get("high_value", False)

        mitre_id = event.get("mitre_technique_id", "")
        mitre_name = event.get("mitre_technique_name", "")

        # ── KILL CHAIN TRACKING ─────────────────────────────────

        if event_type in ("HTTP_ENV_FILE_ACCESS", "HTTP_BACKUP_FILE_ACCESS"):
            attacker["accessed_env_file"] = True
            attacker["risk"] += 5

        if event_type == "HTTP_BACKUP_ACCESS":
            attacker["accessed_backup"] = True
            attacker["risk"] += 3

        if event_type == "SSH_KILL_CHAIN_LOGIN":
            attacker["ssh_kill_chain"] = True
            attacker["risk"] += 10

        # ── RISK SCORING ────────────────────────────────────────

        if attack_type != "BENIGN":
            attacker["malicious_events"] += 1
            attacker["risk"] += 2

        attacker["risk"] += entropy
        attacker["risk"] += attacker["malicious_events"] * 1.5

        if high_value:
            attacker["risk"] += 3

        if len(attacker["services"]) > 1:
            attacker["risk"] += 2

        # ── STATE TRANSITION ────────────────────────────────────

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
            "mitre_technique_id": mitre_id,
            "mitre_technique_name": mitre_name,
            "kill_chain": {
                "accessed_env": attacker["accessed_env_file"],
                "accessed_backup": attacker["accessed_backup"],
                "ssh_confirmed": attacker["ssh_kill_chain"],
                "complete": attacker["ssh_kill_chain"],
            },
            "state_transition": {
                "from": prev_state,
                "to": new_state,
                "reasons": reasons,
            },
        }

    # ── STATE TRANSITIONS ───────────────────────────────────────
    # FIX #6: Transitions are now checked from HIGHEST to LOWEST priority.
    # Previously SUSPICIOUS (1 event) was checked before MALICIOUS (3 events)
    # meaning an attacker could never escalate past SUSPICIOUS.
    # Now the order is: kill chain → confirmed → malicious → suspicious → probing → new
    # Each check uses the CURRENT state so we only ever escalate, never de-escalate.

    def _transition(self, attacker):
        reasons = []

        # Kill chain always wins — absolute highest state
        if attacker["ssh_kill_chain"]:
            reasons.append("kill chain confirmed — HTTP recon led to SSH access")
            return self.KILL_CHAIN_CONFIRMED, reasons

        # Confirmed attack — persistent high-risk
        if attacker["risk"] > 10 and attacker["events"] > 5:
            reasons.append("persistent high-risk attacker")
            return self.CONFIRMED_ATTACK, reasons

        # Malicious — repeated attacks OR high risk score
        if attacker["malicious_events"] >= 3 or attacker["risk"] > 6:
            reasons.append("repeated malicious behaviour or high risk score")
            return self.MALICIOUS, reasons

        # Suspicious — first malicious event detected
        if attacker["malicious_events"] >= 1:
            reasons.append("malicious event detected")
            return self.SUSPICIOUS, reasons

        # Probing — multiple interactions but nothing malicious yet
        if attacker["events"] >= 2 and attacker["state"] == self.NEW:
            reasons.append("multiple interactions observed")
            return self.PROBING, reasons

        # No change
        return attacker["state"], ["no escalation triggered"]

    def _extract_ip(self, event):
        return event.get("details", {}).get("client_ip") or "UNKNOWN"