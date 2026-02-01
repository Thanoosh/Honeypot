# ml/attack_intent_classifier.py

from transformers import pipeline
from typing import Dict


class AttackIntentClassifier:
    """
    Zero-shot ML classifier with security-aware normalization.
    """

    def __init__(self):
        self.classifier = pipeline(
            task="zero-shot-classification",
            model="facebook/bart-large-mnli",
        )

        # Canonical security labels
        self.labels = [
            "SQL Injection",
            "Command Injection",
            "Path Traversal",
            "Brute Force",
            "Credential Access",
            "Reconnaissance",
            "Benign",
        ]

    def classify(self, text: str) -> Dict[str, float]:
        if not text or not text.strip():
            return {"attack_type": "BENIGN", "confidence": 0.0}

        result = self.classifier(
            text,
            candidate_labels=self.labels,
            multi_label=False,
        )

        raw_label = result["labels"][0]
        confidence = float(result["scores"][0])

        # 🔑 SECURITY NORMALIZATION
        attack_type = self._normalize_label(raw_label, text)

        return {
            "attack_type": attack_type,
            "confidence": confidence,
        }

    def _normalize_label(self, label: str, text: str) -> str:
        """
        Maps semantic intent to canonical attack classes.
        """

        t = text.lower()

        # SQL Injection patterns
        if any(x in t for x in ["or 1=1", "union select", "--", "' or '"]):
            return "SQL Injection"

        # Command Injection
        if any(x in t for x in ["; ls", "&&", "| cat", "`id`"]):
            return "Command Injection"

        # Path Traversal
        if "../" in t or "..\\" in t:
            return "Path Traversal"

        # Brute force / credential stuffing
        if "login" in t and label == "Credential Access":
            return "Brute Force"

        return label
