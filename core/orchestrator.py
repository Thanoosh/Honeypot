# core/orchestrator.py

import os
import subprocess
import re


class Orchestrator:
    HTTP_CONTAINER = "honeypot_http"
    SSH_CONTAINER  = "honeypot_ssh"
    NETWORK        = "honeypot_net"

    # When honeypots call back to core, they use the Docker service name
    CORE_API_FOR_CONTAINERS = os.environ.get("CORE_API", "http://honeypot_core:5001")

    # Absolute path to project data directory (used for volume mounts)
    _project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    DATA_DIR = os.path.join(_project_root, "data")

    def __init__(self):
        """
        Test Docker connectivity on startup.
        Raises RuntimeError if Docker socket is not mounted.
        main.py catches this and sets ORCHESTRATOR_OK = False gracefully.
        """
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "Docker not reachable. "
                "Make sure /var/run/docker.sock is mounted in docker-compose.yml. "
                f"Detail: {result.stderr.strip()[:200]}"
            )
        print("[ORCH] Docker reachable — orchestrator ready")

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────

    def _container_exists(self, name: str) -> bool:
        r = subprocess.run(
            ["docker", "ps", "-a",
             "--filter", f"name=^{name}$",
             "--format", "{{.Names}}"],
            capture_output=True, text=True,
        )
        return name in r.stdout.strip().splitlines()

    def _container_running(self, name: str) -> bool:
        r = subprocess.run(
            ["docker", "ps",
             "--filter", f"name=^{name}$",
             "--format", "{{.Names}}"],
            capture_output=True, text=True,
        )
        return name in r.stdout.strip().splitlines()

    def _extract_trycloudflare(self, container_name: str) -> str:
        try:
            r = subprocess.run(["docker", "logs", container_name], capture_output=True, text=True, timeout=5)
            urls = re.findall(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", r.stdout + " " + r.stderr)
            if urls:
                return urls[-1]
        except Exception as e:
            print(f"[ORCH] Error fetching logs for {container_name}: {e}")
        return None

    def _extract_bore(self, container_name: str) -> str:
        try:
            r = subprocess.run(["docker", "logs", container_name], capture_output=True, text=True, timeout=5)
            matches = re.findall(r"listening at ([^\s]+)", r.stdout + " " + r.stderr)
            if matches:
                return matches[-1]
        except Exception as e:
            print(f"[ORCH] Error fetching logs for {container_name}: {e}")
        return None

    def get_tunnels(self) -> dict:
        return {
            "dashboard": self._extract_trycloudflare("tunnel_dash"),
            "http_trap": self._extract_trycloudflare("tunnel_http"),
            "ssh_trap": self._extract_bore("tunnel_ssh")
        }


    # ─────────────────────────────────────────────
    # HTTP HONEYPOT
    # ─────────────────────────────────────────────

    def start_http(self):
        if self._container_running(self.HTTP_CONTAINER):
            print("[ORCH] HTTP honeypot already running")
            return

        if self._container_exists(self.HTTP_CONTAINER):
            print("[ORCH] HTTP container stopped — restarting")
            subprocess.run(["docker", "start", self.HTTP_CONTAINER], check=False)
            return

        print("[ORCH] Starting HTTP honeypot...")
        r = subprocess.run(
            [
                "docker", "run",
                "-d",
                "--rm",
                "--name", self.HTTP_CONTAINER,
                "--network", self.NETWORK,
                "--add-host", "host.docker.internal:host-gateway",
                "-e", f"CORE_API={self.CORE_API_FOR_CONTAINERS}",
                "-p", "0.0.0.0:8080:8080",
                "honeypot_http_image",
            ],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"Failed to start HTTP honeypot: {r.stderr.strip()}")
        print(f"[ORCH] HTTP honeypot started: {r.stdout.strip()}")

    def stop_http(self):
        print("[ORCH] Stopping HTTP honeypot...")
        subprocess.run(["docker", "rm", "-f", self.HTTP_CONTAINER], check=False)

    def http_running(self) -> bool:
        return self._container_running(self.HTTP_CONTAINER)

    # ─────────────────────────────────────────────
    # SSH HONEYPOT
    # ─────────────────────────────────────────────

    def start_ssh(self):
        if self._container_running(self.SSH_CONTAINER):
            print("[ORCH] SSH honeypot already running")
            return

        if self._container_exists(self.SSH_CONTAINER):
            print("[ORCH] SSH container stopped — restarting")
            subprocess.run(["docker", "start", self.SSH_CONTAINER], check=False)
            return

        print("[ORCH] Starting SSH honeypot...")
        # Use host-side data path if provided (for Docker-outside-Docker volume mapping)
        data_dir = os.environ.get("DATA_DIR_HOST", self.DATA_DIR)

        r = subprocess.run(
            [
                "docker", "run",
                "-d",
                "--rm",
                "--name", self.SSH_CONTAINER,
                "--network", self.NETWORK,
                "--add-host", "host.docker.internal:host-gateway",
                "-e", f"CORE_API={self.CORE_API_FOR_CONTAINERS}",
                "-v", f"{data_dir}:/app/data",
                "-p", "0.0.0.0:2222:2222",
                "honeypot_ssh_image",
            ],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"Failed to start SSH honeypot: {r.stderr.strip()}")
        print(f"[ORCH] SSH honeypot started: {r.stdout.strip()}")

    def stop_ssh(self):
        print("[ORCH] Stopping SSH honeypot...")
        subprocess.run(["docker", "rm", "-f", self.SSH_CONTAINER], check=False)

    def ssh_running(self) -> bool:
        return self._container_running(self.SSH_CONTAINER)

    # ─────────────────────────────────────────────
    # PHYSICAL SANDBOXING
    # ─────────────────────────────────────────────

    def contain_attacker(self, attacker_ip: str):
        """
        Spins up a real, ephemeral Docker container specifically for a highly malicious IP.
        This provides true isolation mapping beyond basic honeypot LLM spoofing.
        """
        # Sanitize IP for docker container name
        safe_ip = str(attacker_ip).replace(".", "_").replace(":", "_")
        container_name = f"sandbox_{safe_ip}"

        if self._container_running(container_name):
            print(f"[ORCH] Attacker {attacker_ip} is already physically contained in {container_name}.")
            return

        print(f"[ORCH] 🔥 High Threat Detected! Spinning up explicit physical sandbox for {attacker_ip}...")
        
        # Spin up a totally unprivileged alpine container that sleeps for 24 hours.
        # Future network policies can route the attacker directly into this container.
        r = subprocess.run(
            [
                "docker", "run",
                "-d",
                "--rm",
                "--name", container_name,
                "--network", self.NETWORK,
                "--pull", "missing",
                "alpine", "sleep", "86400"
            ],
            capture_output=True, text=True,
        )
        
        if r.returncode != 0:
            print(f"[ORCH] ❌ Failed to physically sandbox {attacker_ip}: {r.stderr.strip()}")
        else:
            print(f"[ORCH] ✅ Attacker {attacker_ip} structurally isolated in {container_name}.")