import requests
import paramiko
import time

print("[*] Simulating persistent attacker from localhost...")
target_ip = "127.0.0.1"

# 1. Hit HTTP (generates 4 malicious events, Risk +8)
print("[*] Stage 1: Attacking Web App (SQLi)")
for _ in range(4):
    try:
        requests.post(f"http://{target_ip}:8080/login", data={"username":"admin' OR 1=1--"}, timeout=2)
    except:
        pass
    time.sleep(0.5)

# 2. Pivot to SSH (generates cross-service pivot, Risk +2)
print("[*] Stage 2: Pivoting to SSH (Protocol Jump)")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    client.connect(target_ip, port=2222, username="hacker", password="wrongpassword", timeout=3)
except Exception:
    pass

print("[*] Complete! Check your SOC Dashboard for the Lateral Moves increase.")
