import requests
import time

print("[*] Simulating a dumb scanner (Bot Attack)...")
target_ip = "127.0.0.1"

# We spoof the IP so the honeypot thinks it's a brand new attacker!
headers = {"X-Forwarded-For": "100.200.50.11"}

# Just 3 malicious probing events
for i in range(3):
    print(f"[*] Sending probe {i+1}/3 ...")
    try:
        requests.post(f"http://{target_ip}:8080/login", data={"username":"admin' OR 1=1--"}, headers=headers, timeout=2)
    except:
        pass
    time.sleep(0.5)

print("[*] The Bot has triggered AUTOMATED_ATTACK!")
print("[*] Check your SOC Dashboard (Bot Alerts metric should go up).")
