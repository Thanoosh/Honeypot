# forensics/pcap_manager.py
import subprocess
import shutil
import os
import time

class PCAPManager:
    def __init__(self, base_dir="data/pcaps"):
        self.base_dir = base_dir
        self.processes = {}
        self.enabled = self._check_tshark()

        os.makedirs(self.base_dir, exist_ok=True)

    def _check_tshark(self):
        """Check if tshark exists in PATH"""
        if shutil.which("tshark") is None:
            print("[PCAP] WARNING: tshark not found — PCAP disabled")
            return False
        return True

    def start_capture(self, service_name):
        """Start PCAP capture in background (non-blocking)"""
        if not self.enabled:
            return

        if service_name in self.processes:
            return  # already running

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        pcap_path = os.path.join(
            self.base_dir, f"{service_name}_{timestamp}.pcap"
        )

        cmd = [
            "tshark",
            "-i", "any",
            "-w", pcap_path
        ]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.processes[service_name] = proc
            print(f"[PCAP] Started capture for {service_name}")
        except Exception as e:
            print(f"[PCAP] ERROR starting capture ({service_name}): {e}")

    def stop_capture(self, service_name):
        """Stop PCAP capture safely"""
        proc = self.processes.pop(service_name, None)
        if not proc:
            return

        try:
            proc.terminate()
            proc.wait(timeout=5)
            print(f"[PCAP] Stopped capture for {service_name}")
        except Exception:
            proc.kill()
