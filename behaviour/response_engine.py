# behaviour/response_engine.py

from typing import Dict, Any
from behaviour.deception_payloads import (
    fake_sql_db,
    fake_filesystem,
    fake_credentials,
)


class ResponseEngine:
    """
    Decides responses + deception payloads based on behaviour & attack type.
    FIX #7: KILL_CHAIN_CONFIRMED is now handled as a valid behaviour state.
    """

    def decide(self, behaviour: str, attack_type: str, confidence: float) -> Dict[str, Any]:
        behaviour = behaviour.upper()
        attack_type = attack_type.upper()

        if confidence < 0.4:
            return self._allow("low confidence activity")

        # FIX #7: Handle kill chain state — maximum deception response
        if behaviour == "KILL_CHAIN_CONFIRMED":
            return self._deceive(
                "Kill chain complete — attacker used HTTP creds to SSH in",
                payload=fake_credentials(),
            )

        if attack_type == "SQL INJECTION":
            return self._handle_sqli(behaviour)

        if attack_type == "DIRECTORY TRAVERSAL":
            return self._handle_traversal(behaviour)

        if attack_type == "CREDENTIAL ACCESS":
            return self._handle_credentials(behaviour)

        return self._generic(behaviour)

    # ---------------- HANDLERS ----------------

    def _handle_sqli(self, behaviour):
        if behaviour in ("NEW", "PROBING"):
            return self._slowdown("SQLi probing", delay=1)

        return self._deceive(
            "Fake database exposed",
            payload=fake_sql_db(),
        )

    def _handle_traversal(self, behaviour):
        if behaviour == "PROBING":
            return self._deceive(
                "Fake filesystem exposed",
                payload=fake_filesystem(),
            )

        return self._contain("Traversal confirmed")

    def _handle_credentials(self, behaviour):
        if behaviour == "PROBING":
            return self._deceive(
                "Fake credentials leaked",
                payload=fake_credentials(),
            )

        return self._contain("Credential attack")

    def _generic(self, behaviour):
        if behaviour in ("NEW", "PROBING"):
            return self._slowdown("Generic suspicious activity", delay=1)

        return self._contain("Confirmed attack")

    # ---------------- RESPONSE BUILDERS ----------------

    def _allow(self, reason):
        return {
            "action": "ALLOW",
            "delay": 0,
            "deception": False,
            "service_mode": "NORMAL",
            "notes": reason,
        }

    def _slowdown(self, reason, delay):
        return {
            "action": "SLOWDOWN",
            "delay": delay,
            "deception": False,
            "service_mode": "DEGRADED",
            "notes": reason,
        }

    def _deceive(self, reason, payload):
        return {
            "action": "DECEIVE",
            "delay": 0,
            "deception": True,
            "service_mode": "DECEPTION",
            "deception_payload": payload,
            "notes": reason,
        }

    def _contain(self, reason):
        return {
            "action": "CONTAIN",
            "delay": 0,
            "deception": True,
            "service_mode": "CONTAINED",
            "notes": reason,
        }