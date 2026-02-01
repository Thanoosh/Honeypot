# behaviour/behaviour_classifier.py

import numpy as np
from ml.embedding_model import EmbeddingModel
from ml.feature_extractor import FeatureExtractor
from ml.behaviour_model import BehaviourModel
from ml.attack_intent_classifier import AttackIntentClassifier

class BehaviourClassifier:
    def __init__(self):
        self.embedder = EmbeddingModel()
        self.extractor = FeatureExtractor()
        self.intent_classifier = AttackIntentClassifier()

        self.models = {}
        self.last_time = {}

    def process_event(self, event):
        details = event.get("details", {})
        client_ip = details.get("client_ip", "unknown")
        text = str(details)

        if client_ip not in self.models:
            self.models[client_ip] = BehaviourModel()
            self.last_time[client_ip] = None

        # -------- Attack Intent (Zero-shot NLP) --------
        intent = self.intent_classifier.classify(text)

        # -------- Behaviour ML --------
        embedding = self.embedder.embed(text)
        features = self.extractor.extract(text, self.last_time[client_ip])
        self.last_time[client_ip] = features["timestamp"]

        numeric = np.array([
            features["length"],
            features["entropy"],
            features["interval"]
        ])

        vector = np.concatenate([embedding[:10], numeric])

        model = self.models[client_ip]
        model.add_sample(vector)
        behaviour = model.predict(vector)

        return {
            "behaviour": behaviour,
            "attack_type": intent["attack_type"],
            "confidence": intent["confidence"],
            "features": features
        }
