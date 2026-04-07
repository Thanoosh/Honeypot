import sys
import json
from core.main import app

# Simulate a series of events from an attacker IP
attacker_ip = "192.168.1.100"

events = [
    {
        "event_type": "HTTP_GET",
        "client_ip": attacker_ip,
        "details": {"payload": "/admin", "method": "GET"}
    },
    {
        "event_type": "HTTP_POST",
        "client_ip": attacker_ip,
        "details": {"payload": "admin' OR 1=1 --", "method": "POST"}
    },
    {
        "event_type": "HTTP_GET",
        "client_ip": attacker_ip,
        "details": {"payload": "cat /etc/passwd", "method": "GET"}
    },
    {
        "event_type": "SSH_LOGIN_ATTEMPT",
        "client_ip": attacker_ip,
        "details": {"command": "hydra -l root -P pass.txt"}
    }
]

out_logs = []

with app.test_client() as client:
    for idx, event in enumerate(events):
        response = client.post('/event', json=event)
        
        data = response.get_json()
        out_logs.append({
            "event_number": idx + 1,
            "payload": event['details'].get('payload') or event['details'].get('command'),
            "attack_type": data.get('attack_type'),
            "ml_confidence": data.get('confidence'),
            "risk_score": data.get('risk_score'),
            "state": data.get('state_transition', {}).get('to'),
            "ai_class": data.get('ai_classification'),
            "threat_level": data.get('threat_level'),
            "mitre_technique_name": data.get('mitre_technique_name'),
            "mitre_technique_id": data.get('mitre_technique_id'),
            "maneuver_action": data.get('response', {}).get('action')
        })

with open('test_results.json', 'w') as f:
    json.dump(out_logs, f, indent=2)

print("Saved test_results.json")
