# core/resource_manager.py
"""
Stage 5: Resource-Aware Mode Manager
Detects available system RAM and automatically selects the correct
deception mode: Standard (16GB), Eco (8GB), or Legacy (4GB/CPU only).
"""

import psutil
import logging

logger = logging.getLogger(__name__)


class ResourceManager:
    """
    Detects the host machine's available memory and selects the
    appropriate operating mode for the AI components.
    """

    # Memory thresholds in GiB
    STANDARD_THRESHOLD_GB = 12.0   # >= 12 GB → full AI pipeline
    ECO_THRESHOLD_GB = 6.0         # >= 6 GB  → quantized Phi-3 mini, lazy load
    # Below 6 GB → Legacy / deterministic only

    def __init__(self):
        self.mode = self._detect_mode()
        logger.info(f"[ResourceManager] Mode selected: {self.mode}")

    def _available_gb(self) -> float:
        mem = psutil.virtual_memory()
        return mem.available / (1024 ** 3)

    def _total_gb(self) -> float:
        mem = psutil.virtual_memory()
        return mem.total / (1024 ** 3)

    def _detect_mode(self) -> str:
        available = self._available_gb()
        total = self._total_gb()

        logger.info(
            f"[ResourceManager] RAM — Total: {total:.1f} GB | Available: {available:.1f} GB"
        )

        if available >= self.STANDARD_THRESHOLD_GB:
            return "STANDARD"
        elif available >= self.ECO_THRESHOLD_GB:
            return "ECO"
        else:
            return "LEGACY"

    # ------------------------------------------------------------------ #
    # Public interface                                                     #
    # ------------------------------------------------------------------ #

    def get_ollama_model(self) -> str | None:
        """Return the Ollama model name appropriate for the current mode."""
        if self.mode == "STANDARD":
            return "phi3:mini"          # Full 3.8B (Q5 quality)
        elif self.mode == "ECO":
            return "phi3:mini-4k"       # Quantized 4-bit variant (~1.8 GB)
        else:
            return None                 # Legacy — no LLM

    def llm_enabled(self) -> bool:
        return self.mode != "LEGACY"

    def bilstm_enabled(self) -> bool:
        """Bi-LSTM is always enabled (only ~200 MB even in Legacy mode)."""
        return True

    def summary(self) -> dict:
        return {
            "mode": self.mode,
            "total_ram_gb": round(self._total_gb(), 1),
            "available_ram_gb": round(self._available_gb(), 1),
            "llm_enabled": self.llm_enabled(),
            "ollama_model": self.get_ollama_model(),
            "bilstm_enabled": self.bilstm_enabled(),
        }


# Quick self-test
if __name__ == "__main__":
    rm = ResourceManager()
    import json
    print(json.dumps(rm.summary(), indent=2))
