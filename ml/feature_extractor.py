# ml/feature_extractor.py
# ─────────────────────────────────────────────────────────────────────────────
# Rich statistical feature extraction — all operations are O(n) string scans,
# completing in microseconds regardless of hardware. These features feed the
# IsolationForest anomaly detector and enrich the event log.
# ─────────────────────────────────────────────────────────────────────────────

import numpy as np
import math
import time
import re


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string — high entropy = obfuscated/encoded."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return entropy


class FeatureExtractor:
    """
    Extracts a rich 12-dimensional feature vector from a payload/command.
    All features are designed to be discriminating for cybersecurity events
    with zero added latency (all pure-Python string operations).
    """

    # Regex patterns compiled once at import time for speed
    _PIPE_REDIRECT   = re.compile(r"[|>&;]")
    _BRACKETS        = re.compile(r"[\[\]{}()]")
    _TRAVERSAL       = re.compile(r"\.\.[/\\]")
    _HEX_ESCAPE      = re.compile(r"\\x[0-9a-fA-F]{2}")
    _BASE64_TOKEN    = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    _SQL_KEYWORDS    = re.compile(
        r"\b(select|union|insert|update|delete|drop|exec|sleep|cast|"
        r"convert|concat|char|xp_cmdshell|benchmark|INFORMATION_SCHEMA)\b",
        re.IGNORECASE
    )
    _SHELL_KEYWORDS  = re.compile(
        r"\b(wget|curl|nc|bash|sh|python|perl|ruby|php|chmod|chown|"
        r"useradd|passwd|crontab|systemctl|iptables|ssh|nmap|hydra|"
        r"medusa|sqlmap|nikto|metasploit|msfvenom)\b",
        re.IGNORECASE
    )

    def extract(self, text: str, last_time: float = None) -> dict:
        now = time.time()
        delta = now - last_time if last_time else 0.0
        n = len(text) if text else 1
        t = text or ""

        # ── Basic ─────────────────────────────────────────────────────────
        length = len(t)
        entropy = shannon_entropy(t)
        interval = delta

        # ── Character class ratios ─────────────────────────────────────────
        alpha_count   = sum(1 for c in t if c.isalpha())
        digit_count   = sum(1 for c in t if c.isdigit())
        special_count = length - alpha_count - digit_count

        special_char_ratio = special_count / (length or 1)
        digit_ratio        = digit_count   / (length or 1)

        # ── Attack structural signals ──────────────────────────────────────
        pipe_redirect_count = len(self._PIPE_REDIRECT.findall(t))
        bracket_count       = len(self._BRACKETS.findall(t))
        traversal_depth     = len(self._TRAVERSAL.findall(t))  # count of ../ or ..\
        hex_escape_count    = len(self._HEX_ESCAPE.findall(t))
        has_base64_blob     = 1 if self._BASE64_TOKEN.search(t) else 0

        # ── Semantic keyword hits (0-N) ────────────────────────────────────
        sql_keyword_hits   = len(self._SQL_KEYWORDS.findall(t))
        shell_keyword_hits = len(self._SHELL_KEYWORDS.findall(t))

        return {
            # Timing
            "length":             length,
            "interval":           delta,
            "timestamp":          now,
            # Entropy & character composition
            "entropy":            entropy,
            "special_char_ratio": round(special_char_ratio, 4),
            "digit_ratio":        round(digit_ratio, 4),
            # Structural attack indicators
            "pipe_redirect_count": pipe_redirect_count,
            "bracket_count":       bracket_count,
            "traversal_depth":     traversal_depth,
            "hex_escape_count":    hex_escape_count,
            "has_base64_blob":     has_base64_blob,
            # Semantic keyword hits
            "sql_keyword_hits":    sql_keyword_hits,
            "shell_keyword_hits":  shell_keyword_hits,
        }

    def to_vector(self, features: dict) -> list:
        """
        Returns a flat numeric vector suitable for the IsolationForest.
        Order must stay consistent across calls.
        """
        return [
            features["length"],
            features["entropy"],
            features["interval"],
            features["special_char_ratio"],
            features["digit_ratio"],
            features["pipe_redirect_count"],
            features["bracket_count"],
            features["traversal_depth"],
            features["hex_escape_count"],
            features["has_base64_blob"],
            features["sql_keyword_hits"],
            features["shell_keyword_hits"],
        ]
