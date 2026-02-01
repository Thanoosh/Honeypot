# core/orchestrator.py

import subprocess


class Orchestrator:
    def __init__(self):
        self._http_running = False
        self._ssh_running = False

    # ---------------- HTTP ----------------

    def start_http(self):
        if self._http_running:
            print("[ORCH] HTTP honeypot already running")
            return

        print("[ORCH] Starting HTTP honeypot...")
        result = subprocess.run(
            [
                "docker", "run", "-d", "--rm",
                "--name", "honeypot_http",
                "-p", "8080:8080",
                "honeypot_http_image",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print("[ORCH][ERROR] HTTP failed:")
            print(result.stderr.strip())
            self._http_running = False
            return

        self._http_running = True

    def stop_http(self):
        subprocess.run(["docker", "rm", "-f", "honeypot_http"], capture_output=True)
        self._http_running = False

    def http_running(self):
        return self._http_running

    # ---------------- SSH ----------------

    def start_ssh(self):
        if self._ssh_running:
            print("[ORCH] SSH honeypot already running")
            return

        print("[ORCH] Starting SSH honeypot...")
        result = subprocess.run(
            [
                "docker", "run", "-d", "--rm",
                "--name", "honeypot_ssh",
                "-p", "2222:2222",
                "honeypot_ssh_image",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print("[ORCH][ERROR] SSH failed:")
            print(result.stderr.strip())
            self._ssh_running = False
            return

        self._ssh_running = True

    def stop_ssh(self):
        subprocess.run(["docker", "rm", "-f", "honeypot_ssh"], capture_output=True)
        self._ssh_running = False

    def ssh_running(self):
        return self._ssh_running
