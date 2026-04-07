# ml/behaviour_model.py

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from pathlib import Path

MODEL_PATH = Path("data/ml/behaviour_model.joblib")

class BehaviourModel:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.15,
            random_state=42
        )
        self.samples = []
        self.trained = False

        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

        if MODEL_PATH.exists():
            self.model = joblib.load(MODEL_PATH)
            self.trained = True

    def add_sample(self, vector):
        self.samples.append(vector)

        # train earlier (not 20!)
        if len(self.samples) >= 8:
            self.model.fit(self.samples)
            joblib.dump(self.model, MODEL_PATH)
            self.trained = True

    def predict(self, vector):
        if not self.trained:
            return "LEARNING"

        score = self.model.predict([vector])[0]

        if score == -1:
            return "ANOMALOUS"
        return "BENIGN"
