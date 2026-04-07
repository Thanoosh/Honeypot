# behaviour/adaptation_engine.py

from behaviour.maneuvering_engine import ManeuveringEngine


class AdaptationEngine:
    """
    Applies adaptive deception strategies based on attacker behaviour.

    Routes to the ManeuveringEngine which respects the global AI_MODE:
      Tier 1/2 → rich static payloads (no LLM)
      Tier 3   → Phi-3 LLM generates hyper-realistic deceptive output
    """

    def __init__(self):
        self.maneuver = ManeuveringEngine()

    def apply(self, behaviour: str, command: str = None, context: dict = None) -> str:
        """
        Execute adaptation based on behaviour type.
        Returns the customized deceptive output to show the attacker.
        Always returns a non-empty string.

        Args:
            behaviour:  Attacker behaviour classification from the ML pipeline.
            command:    The raw command the attacker typed.
            context:    Runtime context dict (e.g. {'cwd': '/root/secret'}).  Passed
                        through to the ManeuveringEngine so the LLM can generate
                        directory-aware, contextually consistent output.
        """
        # Normalise legacy behaviour state names to attacker class names
        _class_map = {
            "AUTOMATED_ATTACK":     "SCRIPT_BOT",
            "SCRIPT_BOT":           "SCRIPT_BOT",
            "PERSISTENT_ATTACKER":  "PERSISTENT_ATTACKER",
            "APT":                  "APT",
            "CONFIRMED_ATTACK":     "PERSISTENT_ATTACKER",
            "MALICIOUS":            "PERSISTENT_ATTACKER",
            "KILL_CHAIN_CONFIRMED": "APT",
        }
        attacker_class = _class_map.get(behaviour, "PERSISTENT_ATTACKER")

        if command:
            return self.maneuver.apply_maneuver(command, attacker_class, context=context)

        # Fallback: just apply the adaptive delay and return a static payload
        import time
        delay = self.maneuver.adaptive_delay(attacker_class)
        time.sleep(delay)
        return self.maneuver._static_bait("DEFAULT")
