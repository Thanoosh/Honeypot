# core/alert_manager.py

import time
from typing import Dict, Any

class AlertManager:
    """
    Handles real-time alerting for high-risk attacker behavior.
    In a production environment, this would send to Slack/Discord/Email.
    For this demo, it prints prominent alerts to the Core logs.
    """
    CRITICAL_BEHAVIOURS = (
        "AUTOMATED_ATTACK", 
        "PERSISTENT_ATTACKER", 
        "KILL_CHAIN_CONFIRMED",
        "SSH_LOGIN" # Added for demo/verification visibility
    )

    def __init__(self, mode="CONSOLE"):
        self.mode = mode
        print(f"[ALERT] Alert Manager initialized in {mode} mode.")

    def process(self, enriched_event: Dict[str, Any]):
        behaviour = enriched_event.get("behaviour", "NEW")
        event_type = enriched_event.get("event_type", "")
        
        # Only alert on high-severity behaviours OR specific demo events
        if behaviour in self.CRITICAL_BEHAVIOURS or event_type == "SSH_LOGIN":
            self._send_alert(enriched_event)

    def _send_alert(self, event: Dict[str, Any]):
        behaviour = event.get("behaviour")
        risk = event.get("risk_score")
        ip = event.get("details", {}).get("client_ip", "UNKNOWN")
        service = event.get("event_type", "UNKNOWN").split("_")[0]

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        alert_msg = (
            f"\n"
            f"🚨 [{timestamp}] ALERT: CRITICAL BEHAVIOUR DETECTED 🚨\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f" 🛡️  Behaviour: {behaviour}\n"
            f" 🌐  Source IP: {ip}\n"
            f" 🎯  Service:   {service}\n"
            f" 🚩  Risk Score: {risk}/20.0\n"
            f" 📝  Event Type: {event.get('event_type')}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        )
        
        if self.mode == "CONSOLE":
            print(alert_msg)
        
        # Future: Integration with Slack/Discord webhooks would happen here
