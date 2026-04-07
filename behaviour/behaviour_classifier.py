# behaviour/behaviour_classifier.py
# ─────────────────────────────────────────────────────────────────────────────
# LATENCY DESIGN PRINCIPLE:
#   BiLSTM sequence embedding (DistilRoBERTa) is the BEST available model
#   for attacker behaviour profiling. It is kept as-is.
#   However, it must NOT block the live shell response to the attacker.
#   Implementation: last AI classification is cached per-IP.
#   The response returns the cached result; the new embedding runs async.
# ─────────────────────────────────────────────────────────────────────────────

import time
import os
import csv
import subprocess
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any
from behaviour.response_engine import ResponseEngine
from ml.bilstm_model import BiLSTMInterface
from ml.ttp_extractor import TTPExtractor

# One shared executor for LSTM background work
_lstm_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="lstmML")


class BehaviourClassifier:
    # States
    NEW = "NEW"
    PROBING = "PROBING"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    CONFIRMED_ATTACK = "CONFIRMED_ATTACK"
    KILL_CHAIN_CONFIRMED = "KILL_CHAIN_CONFIRMED"

    # Priority order used for escalation comparisons
    STATE_PRIORITY = [NEW, PROBING, SUSPICIOUS, MALICIOUS, CONFIRMED_ATTACK, KILL_CHAIN_CONFIRMED]

    def __init__(self):
        self.attackers = defaultdict(self._init_attacker)
        self.response_engine = ResponseEngine()
        self.lstm = BiLSTMInterface()
        self.ttp_extractor = TTPExtractor()
        # Per-IP cached AI classification (avoids blocking on every event)
        self._ai_cache: Dict[str, str] = defaultdict(lambda: "UNKNOWN (Needs Training)")
        self._ai_cache_lock = threading.Lock()
        # AI mode: 1=Eco, 2=Standard, 3=Advanced (set by core/main.py)
        self.ai_mode = 3

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
            "command_history": [],
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

        # ── TTP MAPPING & DEEP ANALYSIS ─────────────────────────
        # Store command for TTP and LSTM analysis
        if event.get("details", {}).get("payload"):
            attacker["command_history"].append(event["details"]["payload"])
        elif event.get("details", {}).get("command"):
            attacker["command_history"].append(event["details"]["command"])
            
        # Extract MITRE Tactics based on their full history
        ttps = self.ttp_extractor.extract_ttps(attacker["command_history"])
        attacker_scoring = self.ttp_extractor.score_attacker(ttps)
        
        # Override the mitre_id if the extractor found some
        mitre_ids = [t["technique_id"] for t in ttps]
        if mitre_ids:
            mitre_id = ", ".join(mitre_ids)
            mitre_name = ", ".join(t["technique_name"] for t in ttps)

        # ── ASYNC LSTM PROFILING (non-blocking) ──────────────────
        # Tier 1 (Eco): skip expensive BiLSTM — use rule-based state as AI class
        # Tier 2/3: use cached result and trigger background update
        if self.ai_mode >= 2:
            with self._ai_cache_lock:
                ai_behaviour_class = self._ai_cache[ip]
            # Snapshot the history for the background thread (avoid mutation race)
            history_snapshot = list(attacker["command_history"])
            _lstm_executor.submit(self._update_lstm_cache, ip, history_snapshot)
        else:
            ai_behaviour_class = "Eco-Mode (Rule-Based)"

        # ── STATE TRANSITION ────────────────────────────────────

        prev_state = attacker["state"]
        new_state, reasons = self._transition(attacker)
        attacker["state"] = new_state

        # Self-Healing ML Loop Hook
        target_states = (self.MALICIOUS, self.CONFIRMED_ATTACK, self.KILL_CHAIN_CONFIRMED)
        if new_state != prev_state and new_state in target_states:
            self._trigger_ml_feedback(attacker["command_history"])

        # Pass specific attacker class to Response Engine for dynamic baiting
        response = self.response_engine.decide(
            behaviour=ai_behaviour_class if ai_behaviour_class != "UNKNOWN (Needs Training)" else new_state,
            attack_type=attack_type,
            confidence=confidence,
        )

        return {
            "behaviour": new_state,
            "ai_classification": ai_behaviour_class,
            "attack_type": attack_type,
            "confidence": confidence,
            "risk_score": round(attacker["risk"], 2),
            "threat_level": attacker_scoring["threat_level"],
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
            "services": list(attacker["services"]),
        }

    # ── STATE TRANSITIONS ───────────────────────────────────────
    # FIX #6: Transitions are now checked from HIGHEST to LOWEST priority.
    # Previously SUSPICIOUS (1 event) was checked before MALICIOUS (3 events)
    # meaning an attacker could never escalate past SUSPICIOUS.
    # Now the order is: kill chain → confirmed → malicious → suspicious → probing → new
    # Each check uses the CURRENT state so we only ever escalate, never de-escalate.

    def _transition(self, attacker):
        reasons = []

        # Most severe first — Kill chain always wins
        if attacker["ssh_kill_chain"]:
            reasons.append("kill chain confirmed — HTTP recon led to SSH access")
            return self.KILL_CHAIN_CONFIRMED, reasons

        # Confirmed attack — persistent high-risk
        if attacker["risk"] > 10 and attacker["events"] > 5:
            reasons.append("persistent high-risk attacker")
            return self.CONFIRMED_ATTACK, reasons

        # Malicious — repeated malicious behaviour
        if attacker["malicious_events"] >= 3 or attacker["risk"] > 6:
            reasons.append("repeated malicious behaviour")
            return self.MALICIOUS, reasons

        # Suspicious — first malicious event detected
        if attacker["malicious_events"] >= 1:
            reasons.append("malicious event detected")
            return self.SUSPICIOUS, reasons

        # Probing — multiple interactions
        if attacker["events"] >= 2:
            reasons.append("multiple interactions")
            return self.PROBING, reasons

        # No change
        return attacker["state"], ["no escalation triggered"]

    def _update_lstm_cache(self, ip: str, history: list):
        """Runs in background — computes new BiLSTM classification and caches it."""
        try:
            seq_embeddings = self.lstm.get_sequence_embeddings(history)
            result = self.lstm.predict(seq_embeddings)
            with self._ai_cache_lock:
                self._ai_cache[ip] = result
        except Exception as e:
            print(f"[LSTM] Background update failed for {ip}: {e}")

    def _trigger_ml_feedback(self, command_history):
        """Writes command history to feedback and asynchronously retrains the classifiers."""
        if not command_history:
            return
            
        feedback_file = os.path.join(os.path.dirname(__file__), "..", "data", "ml_feedback.csv")
        try:
            os.makedirs(os.path.dirname(feedback_file), exist_ok=True)
            with open(feedback_file, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                for cmd in command_history:
                    # Mark everything from a compromised host sequence as a threat
                    # To keep it simple, we label them as "CMD_INJECTION" or generically "MALICIOUS_SEQUENCE"
                    writer.writerow([cmd, "CMD_INJECTION"])
        except Exception as e:
            print(f"[ML LOOP] Error writing feedback: {e}")
            return

        # Trigger retraining asynchronously
        train_script = os.path.join(os.path.dirname(__file__), "..", "ml", "train_classifiers.py")
        def _run_retrain():
            print("[ML LOOP] Triggering background retraining based on new feedback...")
            subprocess.run(["python", train_script], capture_output=True)
            
        threading.Thread(target=_run_retrain, daemon=True).start()

    def _extract_ip(self, event):
        return event.get("details", {}).get("client_ip") or event.get("client_ip") or "UNKNOWN"