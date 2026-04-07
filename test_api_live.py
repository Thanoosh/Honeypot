import requests
import json
import time

def test_attack_scenario(name, ip, events):
    print(f"\n--- Testing Scenario: {name} ({ip}) ---")
    for idx, event_data in enumerate(events):
        payload = {
            "event_type": event_data["type"],
            "client_ip": ip,
            "details": event_data["details"]
        }
        try:
            start_time = time.time()
            response = requests.post("http://localhost:5001/event", json=payload, timeout=10)
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                print(f"[Step {idx+1}] Payload: {event_data['details'].get('payload') or event_data['details'].get('command')}")
                print(f"       AI Response: {data.get('attack_type')} (Confidence: {data.get('confidence', 0.0):.2f})")
                print(f"       Behaviour: {data.get('behaviour')} | Risk: {data.get('risk_score')}")
                print(f"       Action: {data.get('response', {}).get('action')} | Time: {elapsed:.2f}s")
                if data.get('terminal_output'):
                    print(f"       AI Hallucination: {data.get('terminal_output')[:50]}...")
            else:
                print(f"[Step {idx+1}] Error: {response.status_code}")
        except Exception as e:
            print(f"[Step {idx+1}] Connection Error: {e}")

scenarios = [
    {
        "name": "SQL Injection Probing",
        "ip": "1.2.3.4",
        "events": [
            {"type": "HTTP_POST", "details": {"payload": "admin' OR '1'='1", "method": "POST"}},
            {"type": "HTTP_GET", "details": {"payload": "/etc/passwd", "method": "GET"}},
        ]
    },
    {
        "name": "Advanced SSH Evasion",
        "ip": "5.6.7.8",
        "events": [
            {"type": "SSH_COMMAND", "details": {"command": "echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh"}},
            {"type": "SSH_COMMAND", "details": {"command": "rm -rf /"}},
        ]
    }
]

if __name__ == "__main__":
    for scenario in scenarios:
        test_attack_scenario(scenario["name"], scenario["ip"], scenario["events"])
