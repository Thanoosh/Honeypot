import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.metrics import classification_report, confusion_matrix

# Configuration
MODEL_DIR = "ml/models"
DATA_DIR = "ml/data" # New location for local data
CSV_PATH = os.path.join(DATA_DIR, "csic_database.csv")
MODEL_PATH = os.path.join(MODEL_DIR, "csic_model.joblib")

def ensure_dirs():
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

def generate_mock_data(n_samples=1000):
    """
    Generates synthetic data mimicking the CSIC 2010 dataset structure.
    Useful for testing the pipeline without the full CSV.
    """
    print(f"[MOCK] Generating {n_samples} samples of synthetic CSIC-style data...")
    
    methods = ["GET", "POST", "PUT"]
    urls = [
        "/index.html", "/login", "/search?q=test", "/admin", "/api/v1/user",
        "/login?user=admin' OR 1=1 --", 
        "/search?q=<script>alert(1)</script>",
        "/download?file=../../etc/passwd",
        "/config/db.php?id=1; DROP TABLE users --"
    ]
    
    contents = [
        "", "user=guest&pass=12345", "name=John&email=john@example.com",
        "query=val&id=100", 
        "user=admin&pass=' OR '1'='1",
        "comment=<img src=x onerror=alert(1)>",
        "payload=cat /etc/passwd"
    ]
    
    data = []
    for _ in range(n_samples):
        method = np.random.choice(methods)
        url = np.random.choice(urls)
        content = np.random.choice(contents) if method == "POST" else ""
        
        # Heuristic for labeling mock data
        is_anomalous = any(p in url.lower() or p in content.lower() for p in ["' or", "--", "<script", "../", "drop table", "alert("])
        label = "Anomalous" if is_anomalous else "Normal"
        
        data.append({
            "method": method,
            "url": url,
            "content": content,
            "classification": label
        })
        
    return pd.DataFrame(data)

def clean_text(text):
    """Basic text cleaning for the pipeline."""
    if pd.isna(text):
        return ""
    return str(text).lower().strip()

def run_pipeline():
    ensure_dirs()
    # 1. Load Data
    # Fallback to check original data/ml if it exists (read-only)
    search_path = CSV_PATH
    if not os.path.exists(search_path) and os.path.exists("data/ml/csic_database.csv"):
        search_path = "data/ml/csic_database.csv"

    if os.path.exists(search_path):
        print(f"[LOAD] Reading real dataset from {search_path}...")
        df = pd.read_csv(search_path)
    else:
        print(f"[WARN] {search_path} not found.")
        df = generate_mock_data()

    # 2. Basic Preprocessing
    print("[PRE] Preprocessing features...")
    df['url'] = df['url'].apply(clean_text)
    df['content'] = df['content'].apply(clean_text)
    
    # Binary labels
    df['label'] = (df['classification'] == "Anomalous").astype(int)

    # 3. Features & Target
    X = df[['url', 'content']]
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 4. Build Pipeline
    # Using TF-IDF on URL and Content independently
    preprocessor = ColumnTransformer(
        transformers=[
            ('url_tfidf', TfidfVectorizer(max_features=500, ngram_range=(1, 3)), 'url'),
            ('content_tfidf', TfidfVectorizer(max_features=500, ngram_range=(1, 3)), 'content')
        ]
    )

    pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
    ])

    # 5. Train
    print("[TRAIN] Fitting RandomForest pipeline...")
    pipeline.fit(X_train, y_train)

    # 6. Evaluate
    print("[EVAL] Evaluating model performance...")
    y_pred = pipeline.predict(X_test)
    
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Anomalous"]))
    
    # 7. Persist
    print(f"\n[SAVE] Exporting model to {MODEL_PATH}...")
    joblib.dump(pipeline, MODEL_PATH)
    print("Done.")

if __name__ == "__main__":
    run_pipeline()
