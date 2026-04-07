# behaviour/ollama_client.py
import os
import time
import threading
import logging
import requests

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# The Ollama host can be overridden via environment variable.
# Inside Docker: OLLAMA_HOST=http://honeypot_ollama:11434  (set in compose)
# Local dev:     defaults to localhost.
# ─────────────────────────────────────────────────────────────────────────────
_OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

# Fallback responses per attacker class — shown when LLM is unavailable.
# These must NEVER be empty strings so the honeypot always feels responsive.
_FALLBACK_RESPONSES = {
    "SCRIPT_BOT": (
        "bash: syntax error near unexpected token\n"
        "Permission denied\n"
        "Connection timed out\n"
    ),
    "PERSISTENT_ATTACKER": (
        "root@prod-server-01:/var/www/html# \n"
        "-rw-r--r-- 1 www-data www-data 4096 Jan 10 03:22 .env\n"
        "DB_PASSWORD=Sup3rS3cret!2024\n"
        "API_KEY=sk-live-d3adbeef1234567890\n"
    ),
    "APT": (
        "uid=0(root) gid=0(root) groups=0(root)\n"
        "Linux prod-server-01 5.15.0-101-generic #111-Ubuntu SMP x86_64 GNU/Linux\n"
        "total 128\n"
        "drwxr-xr-x  3 root root  4096 Mar 28 11:42 .\n"
        "-rw-------  1 root root  1024 Mar 28 11:42 .bash_history\n"
    ),
    "DEFAULT": (
        "bash: command not found\n"
        "Segmentation fault (core dumped)\n"
    ),
}


class OllamaClient:
    """
    Resilient wrapper for the local Ollama LLM service.

    Startup logic:
      1. Verifies Ollama service is reachable (non-blocking, retries in background).
      2. Checks if phi3:mini exists locally via `ollama list`.
      3. If NOT found → pulls the model once in a background thread.
      4. Sends a warm-up prompt so the first real attacker response is instant.

    Runtime:
      - Never blocks the Flask request thread.
      - Never returns an empty string — always returns at least a fallback payload.
      - All errors are logged with [OLLAMA] prefix for easy debugging.
    """

    def __init__(self, model_name: str = "phi3:mini"):
        self.model_name = model_name
        self.base_url = _OLLAMA_HOST
        self._ready = False          # True once model is confirmed loaded & warm
        self._warm = False           # True after warm-up prompt succeeds
        self._ready_lock = threading.Lock()

        logger.info(f"[OLLAMA] Starting up with host={self.base_url}, model={model_name}")
        # All startup work is done in a daemon thread — never blocks Flask boot
        threading.Thread(target=self._startup_sequence, daemon=True, name="ollama-init").start()

    # ─────────────────────────────────────────────
    # STARTUP
    # ─────────────────────────────────────────────

    def _startup_sequence(self):
        """Non-blocking startup: wait for service → check model → pull if needed → warm up."""
        if not self._wait_for_service(timeout=120):
            logger.error("[OLLAMA] ❌ Service never became reachable. Eco-Mode fallback active.")
            return

        if not self._model_exists():
            logger.info(f"[OLLAMA] Model '{self.model_name}' not found locally. Pulling now...")
            if not self._pull_model():
                logger.error("[OLLAMA] ❌ Model pull failed. Eco-Mode fallback active.")
                return
        else:
            logger.info(f"[OLLAMA] ✅ Model '{self.model_name}' already cached — skipping download.")

        self._warm_up()

    def _wait_for_service(self, timeout: int = 120) -> bool:
        """Polls the Ollama REST API until it responds or timeout elapses."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = requests.get(f"{self.base_url}/api/tags", timeout=5)
                if r.status_code == 200:
                    logger.info("[OLLAMA] ✅ Service is reachable.")
                    return True
            except Exception:
                pass
            time.sleep(5)
        return False

    def _model_exists(self) -> bool:
        """Returns True if phi3:mini is already in the local model store."""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=10)
            if r.status_code == 200:
                models = r.json().get("models", [])
                names = [m.get("name", "") for m in models]
                return any(self.model_name in n for n in names)
        except Exception as e:
            logger.warning(f"[OLLAMA] Could not check model list: {e}")
        return False

    def _pull_model(self) -> bool:
        """Pulls the model via the Ollama REST API (streaming progress consumed & discarded)."""
        try:
            logger.info(f"[OLLAMA] Pulling {self.model_name} — this may take several minutes on first run...")
            with requests.post(
                f"{self.base_url}/api/pull",
                json={"name": self.model_name, "stream": True},
                stream=True,
                timeout=600,
            ) as resp:
                for line in resp.iter_lines():
                    if line and b'"status":"success"' in line:
                        logger.info(f"[OLLAMA] ✅ '{self.model_name}' successfully pulled and cached.")
                        return True
            # Check if it landed anyway
            return self._model_exists()
        except Exception as e:
            logger.error(f"[OLLAMA] ❌ Pull error: {e}")
            return False

    def _warm_up(self):
        """Sends a one-shot prompt to load model weights into RAM before any attacker arrives."""
        logger.info("[OLLAMA] 🔥 Warming up model...")
        try:
            self._generate("echo test", system_prompt=None, timeout=60)
            with self._ready_lock:
                self._ready = True
                self._warm = True
            logger.info("[OLLAMA] ✅ Model warm and ready for deception!")
        except Exception as e:
            logger.error(f"[OLLAMA] Warm-up failed: {e}")
            # Still mark as ready so we attempt real requests (might work)
            with self._ready_lock:
                self._ready = True

    # ─────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────

    def is_available(self) -> bool:
        """Returns True once the model is confirmed loaded in Ollama."""
        with self._ready_lock:
            return self._ready

    def is_warm(self) -> bool:
        """Returns True once the warm-up prompt succeeded."""
        with self._ready_lock:
            return self._warm

    def generate_response(self, prompt: str, system_prompt: str = None,
                          attacker_class: str = "DEFAULT") -> str:
        """
        Generate a deceptive LLM response.

        NEVER returns an empty string:
        - If unavailable → deterministic fallback based on attacker_class.
        - If generation fails → fallback + error log.
        """
        if not self.is_available():
            logger.warning("[OLLAMA] Not ready — returning fallback payload.")
            return self._get_fallback(attacker_class)

        try:
            result = self._generate(prompt, system_prompt, timeout=8)  # Hard cap: never block >8s
            if result and result.strip():
                return result
            logger.warning("[OLLAMA] Empty response from LLM — using fallback.")
            return self._get_fallback(attacker_class)
        except Exception as e:
            logger.error(f"[OLLAMA] ❌ Generation error: {e}")
            return self._get_fallback(attacker_class)

    # ─────────────────────────────────────────────
    # INTERNALS
    # ─────────────────────────────────────────────

    def _generate(self, prompt: str, system_prompt: str = None, timeout: int = 30) -> str:
        """Raw HTTP call to Ollama generate endpoint."""
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "num_predict": 100,   # SSH responses are short; 100 tokens is plenty
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        r = requests.post(
            f"{self.base_url}/api/generate",
            json=payload,
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json().get("response", "")

    def _get_fallback(self, attacker_class: str) -> str:
        return _FALLBACK_RESPONSES.get(attacker_class, _FALLBACK_RESPONSES["DEFAULT"])

    # Legacy compatibility (used by old code calling pull_model directly)
    def pull_model(self):
        self._pull_model()
