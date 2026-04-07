import sys
import os
from unittest.mock import MagicMock

# Add current directory to path so we can import ml
sys.path.append(os.getcwd())

# Mock joblib to avoid loading the actual model if it's missing or slow
import joblib
joblib.load = MagicMock(return_value=None)

# Mock transformers pipeline to avoid downloading/loading heavy models
import transformers
transformers.pipeline = MagicMock(return_value=None)

from ml.attack_intent_classifier import AttackIntentClassifier

def test_classifier():
    print("Initializing Classifier (Mocked Stage 1 & 2)...")
    clf = AttackIntentClassifier()
    clf.ai_mode = 3
    
    test_cases = [
        {"payload": "admin' OR '1'='1", "expected": "SQL Injection"},
        {"payload": "rm -rf /", "expected": "Command Injection"},
        {"payload": "dd if=/dev/zero of=/dev/sda", "expected": "Command Injection"},
        {"payload": "whoami", "expected": "Reconnaissance"},
        {"payload": "ls -la", "expected": "Command Injection"}, # Note: "; ls" triggers it, but base "ls" might not depending on rules
        {"payload": "cat /etc/passwd", "expected": "BENIGN"} # Standard RF model would catch this, rules might not if not explicitly added
    ]
    
    print("\n--- Verifying Logic Overrides ---")
    for tc in test_cases:
        # We call _rule_classify directly to verify the "Power Rules"
        result = clf._rule_classify(tc["payload"])
        print(f"Payload: {tc['payload']:<30} | Rule Result: {result:<20} | Match: {result == tc['expected']}")

if __name__ == "__main__":
    test_classifier()
