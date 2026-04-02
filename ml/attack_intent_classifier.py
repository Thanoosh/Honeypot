# ml/attack_intent_classifier.py

import os
import joblib
import pandas as pd
import threading
from transformers import pipeline
from typing import Dict, Any

MODEL_PATH = "ml/models/csic_model.joblib"


class AttackIntentClassifier:
    """
    Zero-shot ML classifier with security-aware normalization.
    """

    def __init__(self):
        # 1. Zero-shot model (Stage 2) - Load in background
        self.zero_shot = None
        print("[ML] Starting background load for Zero-shot DistilBART model (Stage 2)...")
        threading.Thread(target=self._load_model, daemon=True).start()

        # 2. Scikit-learn model (Stage 1)
        self.fast_model = None
        if os.path.exists(MODEL_PATH):
            print(f"[ML] Loading fast Scikit-learn model from {MODEL_PATH} (Stage 1)...")
            self.fast_model = joblib.load(MODEL_PATH)
        else:
            print(f"[ML] WARN: {MODEL_PATH} not found. Running in Zero-shot only mode.")

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

    def _load_model(self):
        try:
            self.zero_shot = pipeline(
                task="zero-shot-classification",
                model="valhalla/distilbart-mnli-12-1",
            )
            print("[ML] ✅ Zero-shot DistilBART model fully loaded and ready!")
        except Exception as e:
            print(f"[ML] ❌ Error loading DistilBART: {e}")

    def classify(self, text: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Hybrid classification: fast Sklearn check followed by deep Zero-shot analysis.
        """
        if not text or not text.strip():
            return {
                "attack_type": "BENIGN",
                "confidence": 0.0,
                "fast_path": True,
                "model": "rule-engine"
            }

        # --- STAGE 1: Fast Anomaly Detection (Sklearn) ---
        is_anomalous = False
        fast_confidence = 0.0

        if self.fast_model and context and "method" in context:
            # Construct DataFrame for the pipeline
            df = pd.DataFrame([{
                "method": context.get("method", "GET"),
                "url": context.get("url", text if context.get("method") == "GET" else ""),
                "content": context.get("content", text if context.get("method") == "POST" else "")
            }])
            
            # Predict
            pred = self.fast_model.predict(df)[0]
            probs = self.fast_model.predict_proba(df)[0]
            is_anomalous = (pred == 1)
            fast_confidence = float(max(probs))

            # If it's definitely normal, we can return early (Fast Path)
            if not is_anomalous and fast_confidence > 0.9:
                return {
                    "attack_type": "BENIGN",
                    "confidence": fast_confidence,
                    "fast_path": True,
                    "model": "scikit-learn"
                }

        # --- STAGE 2: Deep Intent Classification (Zero-shot) ---
        if self.zero_shot is None:
            print(f"[ML] Deep analysis skipped (model still loading) for: {text[:50]}...")
            return {
                "attack_type": "UNKNOWN (Model Loading)",
                "confidence": fast_confidence if is_anomalous else 0.0,
                "fast_path": True,
                "model": "scikit-learn (fallback)"
            }

        print(f"[ML] Performing deep analysis on: {text[:50]}...")
        result = self.zero_shot(
            text,
            candidate_labels=self.labels,
            multi_label=False,
        )

        raw_label = result["labels"][0]
        deep_confidence = float(result["scores"][0])

        # Security Normalization
        attack_type = self._normalize_label(raw_label, text)
        
        # Combine confidences if both models agreed
        final_confidence = max(deep_confidence, fast_confidence) if is_anomalous else deep_confidence

        return {
            "attack_type": attack_type,
            "confidence": round(final_confidence, 4),
            "fast_path": False,
            "model": "hybrid (sk + zero-shot)"
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
