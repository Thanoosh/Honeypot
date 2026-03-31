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

    # Kill chain — attacker used HTTP to find SSH creds then logged in via SSH
    KILL_CHAIN = "KILL_CHAIN_CONFIRMED"

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
            # Kill chain tracking
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

        # MITRE technique from HTTP service
        mitre_id = event.get("mitre_technique_id", "")
        mitre_name = event.get("mitre_technique_name", "")

        # ── KILL CHAIN TRACKING ────────────────────────────────
        # Track attacker's progression from HTTP recon to SSH access

        # Stage 1 — attacker found .env or backup files via HTTP
        if event_type in ("HTTP_ENV_FILE_ACCESS", "HTTP_BACKUP_FILE_ACCESS"):
            attacker["accessed_env_file"] = True
            attacker["risk"] += 5  # high risk jump for credential access

        if event_type == "HTTP_BACKUP_ACCESS":
            attacker["accessed_backup"] = True
            attacker["risk"] += 3

        # Stage 2 — attacker used SSH with kill chain credentials
        if event_type == "SSH_KILL_CHAIN_LOGIN":
            attacker["ssh_kill_chain"] = True
            attacker["risk"] += 10  # maximum risk

        # ── RISK SCORING ────────────────────────────────────────
        if attack_type != "BENIGN":
            attacker["malicious_events"] += 1
            attacker["risk"] += 2

        attacker["risk"] += entropy
        attacker["risk"] += attacker["malicious_events"] * 1.5

        if high_value:
            attacker["risk"] += 3

        # Cross-service pivot bonus
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

    def _transition(self, attacker):
        reasons = []

        # Kill chain always wins — highest state
        if attacker["ssh_kill_chain"]:
            reasons.append("kill chain confirmed — HTTP recon led to SSH access")
            return self.KILL_CHAIN, reasons

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