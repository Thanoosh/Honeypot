# behaviour/adaptation_engine.py

import time


class AdaptationEngine:
    """
    Applies adaptive deception strategies based on attacker behaviour.
    """

    def apply(self, behaviour: str):
        """
        Execute adaptation based on behaviour type.
        """
        if behaviour == "AUTOMATED_ATTACK":
            # Slow down automated tools
            time.sleep(2)

        elif behaviour == "PERSISTENT_ATTACKER":
            # Heavier delay to frustrate attacker
            time.sleep(4)

        # SINGLE_PROBE and others: no delay
