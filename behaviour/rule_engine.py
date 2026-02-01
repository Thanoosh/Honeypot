# behaviour/rule_engine.py

class RuleEngine:
    """
    Rule-based behaviour classification engine.
    """

    def classify(self, features: dict) -> str:
        count = features["attack_count"]
        interval = features["avg_interval"]

        if count == 1:
            return "SINGLE_PROBE"

        if interval is not None and interval < 2:
            return "AUTOMATED_ATTACK"

        if count >= 3:
            return "PERSISTENT_ATTACKER"

        return "UNKNOWN"
