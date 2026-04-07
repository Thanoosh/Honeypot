# ml/attack_intent_classifier.py
# ─────────────────────────────────────────────────────────────────────────────
# LATENCY DESIGN PRINCIPLE:
#   This classifier MUST NOT block the honeypot's response to the attacker.
#   Stage 1 (sklearn) returns in <2ms via the "fast path".
#   Stage 2 (DistilBART zero-shot) is the BEST available model for deep NLP
#   intent understanding — but it runs in a background thread and its results
#   are cached. The honeypot shell responds immediately while the analysis is
#   enriched in the background and persisted to the next log entry.
# ─────────────────────────────────────────────────────────────────────────────

import os
import joblib
import hashlib
import threading
import base64
import binascii
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any

from transformers import pipeline

MODEL_PATH = "ml/models/rf_classifier.joblib"

# Shared thread pool — limits to 2 workers so we never starve the CPU
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="zeroshotML")


class AttackIntentClassifier:
    """
    Hybrid classifier with strict non-blocking design:
      Stage 1 — TF-IDF + Random Forest (synchronous, <2ms)
      Stage 2 — DistilBART zero-shot (async background thread, result cached)
    """

    def __init__(self):
        # Stage 1: Fast sklearn model
        self.fast_model = None
        if os.path.exists(MODEL_PATH):
            print(f"[ML] Loading fast Scikit-learn model from {MODEL_PATH} (Stage 1)...")
            self.fast_model = joblib.load(MODEL_PATH)
        else:
            print(f"[ML] WARN: {MODEL_PATH} not found. Stage 1 unavailable.")

        # Stage 2: Best zero-shot model — loaded async, never blocks a request
        self.zero_shot = None
        self._zs_ready = threading.Event()
        print("[ML] Starting background load for Zero-shot DistilBART (Stage 2)...")
        threading.Thread(target=self._load_zero_shot, daemon=True).start()

        # Cache: payload_hash → deep result dict
        # LRU-style: capped at 1024 entries
        self._cache: Dict[str, Dict] = {}
        self._cache_lock = threading.Lock()
        self._cache_max = 1024

        # AI mode: 1=Eco (rule-only), 2=Standard (sklearn), 3=Advanced (sklearn+zero-shot)
        # Set by core/main.py live — no restart required
        self.ai_mode = 3

        # Canonical attack label set
        self.labels = [
            "SQL Injection",
            "Command Injection",
            "Path Traversal",
            "Brute Force",
            "Credential Access",
            "Reconnaissance",
            "Benign",
        ]

    # ─────────────────────────────────────────────
    # INTERNAL: model loading
    # ─────────────────────────────────────────────

    def _load_zero_shot(self):
        try:
            self.zero_shot = pipeline(
                task="zero-shot-classification",
                model="valhalla/distilbart-mnli-12-1",
            )
            self._zs_ready.set()
            print("[ML] ✅ Zero-shot DistilBART fully loaded and ready!")
        except Exception as e:
            print(f"[ML] ❌ Error loading DistilBART: {e}")

    def _payload_hash(self, text: str) -> str:
        return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()

    def _cache_get(self, key: str):
        with self._cache_lock:
            return self._cache.get(key)

    def _cache_set(self, key: str, value: Dict):
        with self._cache_lock:
            if len(self._cache) >= self._cache_max:
                # Evict oldest entry
                oldest = next(iter(self._cache))
                del self._cache[oldest]
            self._cache[key] = value

    # ─────────────────────────────────────────────
    # INTERNAL: async deep analysis
    # ─────────────────────────────────────────────

    def _run_zero_shot_async(self, text: str, payload_hash: str):
        """Runs in background thread. Caches result when done."""
        if not self.zero_shot:
            return
        try:
            result = self.zero_shot(text, candidate_labels=self.labels, multi_label=False)
            raw_label = result["labels"][0]
            deep_confidence = float(result["scores"][0])
            attack_type = self._normalize_label(raw_label, text)
            self._cache_set(payload_hash, {
                "attack_type": attack_type,
                "confidence": round(deep_confidence, 4),
                "fast_path": False,
                "model": "distilbart-zero-shot",
            })
            print(f"[ML] 🔍 Deep async result cached: {attack_type} ({deep_confidence:.2f})")
        except Exception as e:
            print(f"[ML] ❌ Async zero-shot error: {e}")

    # ─────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────

    def classify(self, text: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        RETURNS IMMEDIATELY (<2ms) using Stage 1.
        Stage 2 deep analysis is submitted to a background thread.
        Any previous deep result for this exact payload is returned if cached.
        """
        if not text or not text.strip():
            return {"attack_type": "BENIGN", "confidence": 0.0, "fast_path": True, "model": "rule-engine"}

        # De-obfuscate before analysis
        text = self._preprocess_payload(text)
        ph = self._payload_hash(text)

        # Tier 1 (Eco): rule-based keyword detection only — no ML models invoked
        if self.ai_mode < 2:
            detected = self._rule_classify(text)
            return {
                "attack_type": detected,
                "confidence": 0.75 if detected != "BENIGN" else 0.5,
                "fast_path": True,
                "model": "rule-engine (eco-mode)",
            }

        # ── Check cache first (zero-shot result from a prior background run) ──
        cached = self._cache_get(ph)
        if cached:
            return {**cached, "from_cache": True}

        # ── Stage 1: Fast sklearn path + Power Rules ─────────────────────────
        # Check rules first as a high-confidence safety net
        rule_pred = self._rule_classify(text)
        
        fast_pred = "BENIGN"
        fast_confidence = 0.0
        is_anomalous = False

        if self.fast_model:
            probs = self.fast_model.predict_proba([text])[0]
            fast_pred = self.fast_model.classes_[probs.argmax()]
            fast_confidence = float(max(probs))
            
            # If rules found something but ML didn't, or vice-versa, prioritize rules for known patterns
            if rule_pred != "BENIGN":
                fast_pred = rule_pred
                fast_confidence = max(fast_confidence, 0.95) # Boost confidence for rule matches
            
            is_anomalous = fast_pred != "BENIGN"

            # Definitely benign with high confidence → return fast, skip deep
            if not is_anomalous and fast_confidence > 0.85:
                return {
                    "attack_type": "BENIGN",
                    "confidence": fast_confidence,
                    "fast_path": True,
                    "model": "scikit-learn",
                }

        # ── Stage 2: Submit deep analysis to background (non-blocking) ──────
        # Only in Tier 3 (Advanced) mode
        if self.ai_mode >= 3 and self.zero_shot is not None:
            _executor.submit(self._run_zero_shot_async, text, ph)
        elif self.ai_mode >= 3 and self._zs_ready.is_set() is False:
            print(f"[ML] Deep analysis queued (model still loading) for: {text[:50]}")

        # Return Stage 1 result immediately — the attacker never waits
        return {
            "attack_type": fast_pred if self.fast_model else "UNKNOWN",
            "confidence": round(fast_confidence, 4),
            "fast_path": True,
            "model": "scikit-learn (deep pending)",
        }

    # ─────────────────────────────────────────────
    # INTERNAL: normalization & preprocessing
    # ─────────────────────────────────────────────

    def _normalize_label(self, label: str, text: str) -> str:
        t = text.lower()
        if any(x in t for x in ["or 1=1", "union select", "sleep(", "xp_cmdshell", "' or '", "-- -"]):
            return "SQL Injection"
        if any(x in t for x in ["; ls", "&&", "| cat", "`id`", ";bash", "bin/sh", "bin/bash", "rm -rf", "rm -f", "dd if=", "mkfs", "> /dev/"]):
            return "Command Injection"
        if "../" in t or "..\\" in t:
            return "Path Traversal"
        if "login" in t and label == "Credential Access":
            return "Brute Force"
        return label

    def _rule_classify(self, text: str) -> str:
        """Pure keyword rule engine — used in Tier 1 (Eco) mode with zero ML overhead."""
        t = text.lower()
        if any(x in t for x in ["or 1=1", "union select", "sleep(", "xp_cmdshell", "' or '", "-- -", "sqlmap"]):
            return "SQL Injection"
        if any(x in t for x in ["; ls", "&&", "| cat", "`id`", ";bash", "bin/sh", "/bin/bash", "eval(", "exec(", "rm -rf", "rm -f", "dd if=", "mkfs"]):
            return "Command Injection"
        if "../" in t or "..\\" in t or "%2e%2e" in t:
            return "Path Traversal"
        if any(x in t for x in ["hydra", "medusa", "brute", "/login", "password=", "passwd"]):
            return "Brute Force"
        if any(x in t for x in ["wget ", "curl ", "nc ", "netcat", "base64", "whoami", "id", "hostname", "uname", "ps aux", "netstat", "ip addr"]):
            return "Reconnaissance"
        return "BENIGN"

    def _preprocess_payload(self, text: str) -> str:
        """Decodes common obfuscation layers (hex, base64, SQL comments) before analysis."""
        text = text.replace("/**/", " ")
        previous_text = ""
        loop_counter = 0

        while text != previous_text and loop_counter < 5:
            previous_text = text
            loop_counter += 1

            # Hex decoding (\x72\x6d...)
            if r"\x" in text:
                try:
                    for match in re.finditer(r"(?:\\x[0-9a-fA-F]{2})+", text):
                        hex_chunk = match.group(0)
                        hex_clean = hex_chunk.replace(r"\x", "")
                        try:
                            decoded = bytes.fromhex(hex_clean).decode("utf-8", errors="ignore")
                            text = text.replace(hex_chunk, decoded)
                        except Exception:
                            pass
                except Exception:
                    pass

            # Base64 decoding
            b64_matches = re.findall(
                r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", text
            )
            for b64 in b64_matches:
                try:
                    decoded = base64.b64decode(b64).decode("utf-8")
                    if decoded.isprintable() and len(decoded) > 1:
                        text = text.replace(b64, decoded)
                except Exception:
                    continue

            # Shell token distancing
            text = text.replace("$@", "").replace('""', "").replace("''", "")

        return text
