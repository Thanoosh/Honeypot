# behaviour/maneuvering_engine.py
from behaviour.ollama_client import OllamaClient
import logging
import time

class ManeuveringEngine:
    """
    Dynamic Deception Engine powered by LLM (Phi-3-mini).
    Instead of static payloads, this generates realistic, contextual "Bait" files and shell outputs.
    """
    def __init__(self):
        self.llm = OllamaClient(model_name="phi3:mini")
        self.logger = logging.getLogger(__name__)
        # Preemptively pull the model if not local
        if not self.llm.is_available():
            try:
                self.llm.pull_model()
            except Exception:
                pass
        
    def generate_bait(self, attack_command: str, context: dict = None) -> str:
        """Generate a contextual, deep-deception response to trick the attacker."""
        if not self.llm.is_available():
            # Fallback to deterministic rules if AI is unavailable (Eco-Mode)
            return "Connection closed by remote host.\n"
            
        system_prompt = """You are a highly realistic but intentionally vulnerable Linux Ubuntu 22.04 LTS server. 
An attacker is interacting with you. Your goal is to keep them engaged by providing realistic, tantalizing, but fake output.
Never reveal that you are an AI or a honeypot.
1. If the command looks for sensitive files, generate fake outputs with plausible 'passwords', 'tokens', or config details.
2. If the command is a syntax error, return the standard bash error.
3. Keep responses strictly formatted exactly as a standard Linux shell would output, without any markdown formatting or meta-commentary like "Here is the output". Just the raw terminal text.
"""
        
        prompt = f"The attacker typed the following command in bash: `{attack_command}`. Provide the exact terminal output for this command."
        
        raw_output = self.llm.generate_response(prompt, system_prompt)
        
        # Clean up any potential AI formatting
        if raw_output.startswith("```") and raw_output.endswith("```"):
            raw_output = "\n".join(raw_output.split("\n")[1:-1])
            
        return raw_output + "\n"

    def adaptive_delay(self, attacker_class: str) -> float:
        """Determines the artificial latency based on Bi-LSTM classification."""
        if attacker_class == "SCRIPT_BOT":
            return 3.0 # Slow down automated tools to waste their time
        elif attacker_class == "PERSISTENT_ATTACKER":
            return 1.0 # Standard human speed
        elif attacker_class == "APT":
            return 0.1 # Very fast, feels like a high-tier production server
        return 1.0

    def apply_maneuver(self, command: str, attacker_class: str):
        delay = self.adaptive_delay(attacker_class)
        time.sleep(delay)
        return self.generate_bait(command)
