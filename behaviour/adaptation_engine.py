# behaviour/adaptation_engine.py

from behaviour.maneuvering_engine import ManeuveringEngine

class AdaptationEngine:
    """
    Applies adaptive deception strategies based on attacker behaviour
    using the AI-driven Maneuvering Engine.
    """

    def __init__(self):
        self.maneuver = ManeuveringEngine()

    def apply(self, behaviour: str, command: str = None) -> str:
        """
        Execute adaptation based on behaviour type.
        Returns the customized deceptive "bait" output to show the attacker.
        """
        # Map old behaviour states to new classes if necessary
        attacker_class = "SCRIPT_BOT" if behaviour == "AUTOMATED_ATTACK" else behaviour
        
        # If we have a specific command, do full deep deception
        if command:
            return self.maneuver.apply_maneuver(command, attacker_class)
            
        # Fallback to just delay if no command context provided
        delay = self.maneuver.adaptive_delay(attacker_class)
        import time
        time.sleep(delay)
        return ""
