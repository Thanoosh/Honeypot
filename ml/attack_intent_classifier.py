# ml/attack_intent_classifier.py

from transformers import pipeline
import threading
import os


class AttackIntentClassifier:
    def __init__(self):
        self._classifier = None
        self._lock = threading.Lock()

        # Path to OFFLINE model directory
        self.model_path = os.path.join(
            os.getcwd(),
            "models",
            "bart-large-mnli"
        )

        self.labels = [
            "SQL injection attack",
            "Cross-site scripting attack",
            "Command injection attack",
            "Path traversal attack",
            "Brute force login attempt",
            "Reconnaissance activity",
            "Benign user activity"
        ]

    def _load_model(self):
        # Load model strictly from local files
        self._classifier = pipeline(
            "zero-shot-classification",
            model=self.model_path,
            local_files_only=True
        )

    def classify(self, text: str):
        if not text or not isinstance(text, str):
            return {"attack_type": "UNKNOWN", "confidence": 0.0}

        # Lazy-load model on first use
        if self._classifier is None:
            with self._lock:
                if self._classifier is None:
                    try:
                        print("[ML] Loading offline BART MNLI model...")
                        self._load_model()
                        print("[ML] Offline BART model loaded successfully")
                    except Exception as e:
                        print(f"[ML] Failed to load offline intent model: {e}")
                        return {"attack_type": "UNKNOWN", "confidence": 0.0}

        result = self._classifier(
            text,
            self.labels,
            multi_label=False
        )

        return {
            "attack_type": result["labels"][0],
            "confidence": float(result["scores"][0])
        }
