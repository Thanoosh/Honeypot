import json
from core.main import app

scenarios = {
    "Obfuscated_Polymorphic_Attacker": {
        "ip": "203.0.113.88",
        "events": [
            # The attacker tries to hide the SQLi payload by breaking it up, hoping to bypass the TF-IDF fast model
            {"event_type": "HTTP_POST", "details": {"payload": "ad'/**/min' union/**/all/**/select", "method": "POST"}},
            # Base64 encoded payload execution attempt
            {"event_type": "SSH_COMMAND", "details": {"command": "echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh"}},
            # Hex encoded payload
            {"event_type": "SSH_COMMAND", "details": {"command": "\\x72\\x6d\\x20\\x2d\\x72\\x66\\x20\\x2f"}},
        ]
    },
    "Low_and_Slow_Loris": {
        "ip": "10.0.0.42",
        "events": [
            # Normal looking payloads stretched out (we'll just simulate them sequentially here)
            {"event_type": "HTTP_GET", "details": {"payload": "/images/logo.png", "method": "GET"}},
            {"event_type": "HTTP_GET", "details": {"payload": "/css/main.css", "method": "GET"}},
            {"event_type": "HTTP_GET", "details": {"payload": "/contact?input=test", "method": "GET"}},
            # Tiny piece of credential scraping
            {"event_type": "HTTP_GET", "details": {"payload": "/.env.backup", "method": "GET"}},
        ]
    }
}

results = {}

with app.test_client() as client:
    for profile_name, data in scenarios.items():
        profile_logs = []
        for idx, event in enumerate(data["events"]):
            event["client_ip"] = data["ip"]
            response = client.post('/event', json=event)
            json_data = response.get_json()
            
            log_entry = {
                "step": idx + 1,
                "payload_or_command": event['details'].get('payload') or event['details'].get('command'),
                "identified_attack": json_data.get('attack_type'),
                "current_risk_score": json_data.get('risk_score'),
                "behaviour_state": json_data.get('state_transition', {}).get('to'),
            }
            profile_logs.append(log_entry)
        results[profile_name] = profile_logs

with open('scenario_results_advanced.json', 'w') as f:
    json.dump(results, f, indent=2)

print("Advanced scenarios saved.")
