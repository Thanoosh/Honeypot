import os
import sys
from typing import Any, Dict

# Ensure project root is in path
sys.path.append(os.getcwd())

from ml.attack_intent_classifier import AttackIntentClassifier

def test_classifier():
    print("--- [TEST] Initializing Hybrid Classifier ---")
    classifier = AttackIntentClassifier()
    
    # 1. Normal Request (Fast Path Test)
    print("\n--- [TEST 1] Normal GET Request ---")
    normal_text = "/index.html"
    normal_context = {"method": "GET", "url": "/index.html", "content": ""}
    
    result = classifier.classify(normal_text, context=normal_context)
    print(f"Result: {result}")
    
    # 2. SQL Injection (Deep Path Test)
    print("\n--- [TEST 2] SQL Injection Attack ---")
    sqli_text = "admin' OR 1=1 --"
    sqli_context = {"method": "POST", "url": "/login", "content": "user=admin' OR 1=1 --"}
    
    result = classifier.classify(sqli_text, context=sqli_context)
    print(f"Result: {result}")

    # 3. Path Traversal (Deep Path Test)
    print("\n--- [TEST 3] Path Traversal Attack ---")
    pt_text = "../../etc/passwd"
    pt_context = {"method": "GET", "url": "/download?file=../../etc/passwd", "content": ""}
    
    result = classifier.classify(pt_text, context=pt_context)
    print(f"Result: {result}")

if __name__ == "__main__":
    test_classifier()
