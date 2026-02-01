# core/orchestrator.py

import subprocess


class Orchestrator:
    HTTP_CONTAINER = "honeypot_http"
    SSH_CONTAINER = "honeypot_ssh"

    # ---------------- HELPERS ----------------

    def _container_exists(self, name: str) -> bool:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
        )
        return name in result.stdout.strip().splitlines()

    def _container_running(self, name: str) -> bool:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
        )
        return name in result.stdout.strip().splitlines()

    # ---------------- HTTP ----------------

    def start_http(self):
        if self._container_running(self.HTTP_CONTAINER):
            print("[ORCH] HTTP honeypot already running (docker)")
            return

        if self._container_exists(self.HTTP_CONTAINER):
            print("[ORCH] HTTP container exists but stopped, starting...")
            subprocess.run(["docker", "start", self.HTTP_CONTAINER], check=False)
            return

        print("[ORCH] Starting HTTP honeypot...")
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                self.HTTP_CONTAINER,
                "-p",
                "8080:8080",
                "honeypot_http_image",
            ],
            check=False,
        )

    def stop_http(self):
        print("[ORCH] Stopping HTTP honeypot...")
        subprocess.run(["docker", "rm", "-f", self.HTTP_CONTAINER], check=False)

    def http_running(self):
        return self._container_running(self.HTTP_CONTAINER)

    # ---------------- SSH ----------------

    def start_ssh(self):
        if self._container_running(self.SSH_CONTAINER):
            print("[ORCH] SSH honeypot already running (docker)")
            return

        if self._container_exists(self.SSH_CONTAINER):
            print("[ORCH] SSH container exists but stopped, starting...")
            subprocess.run(["docker", "start", self.SSH_CONTAINER], check=False)
            return

        print("[ORCH] Starting SSH honeypot...")
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                self.SSH_CONTAINER,
                "-p",
                "2222:2222",
                "honeypot_ssh_image",
            ],
            check=False,
        )

    def stop_ssh(self):
        print("[ORCH] Stopping SSH honeypot...")
        subprocess.run(["docker", "rm", "-f", self.SSH_CONTAINER], check=False)

    def ssh_running(self):
        return self._container_running(self.SSH_CONTAINER)
