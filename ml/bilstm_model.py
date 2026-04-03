import torch
import torch.nn as nn
import os
import joblib

class BehaviouralBiLSTM(nn.Module):
    """
    Bi-Directional LSTM for analyzing the sequence of attacker commands.
    It takes an sequence of command embeddings and predicts the attacker's skill level/behavior type.
    """
    def __init__(self, input_dim=768, hidden_dim=128, num_layers=2, num_classes=3):
        super(BehaviouralBiLSTM, self).__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        # Bi-LSTM Layer
        self.lstm = nn.LSTM(
            input_dim, 
            hidden_dim, 
            num_layers, 
            batch_first=True, 
            bidirectional=True
        )
        
        # Dense Layer mapping to Classes (e.g. Script-Kiddie, Automated Bot, Advanced Persistent Threat)
        self.fc = nn.Linear(hidden_dim * 2, num_classes)
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        # x shape: (batch_size, sequence_length, input_dim)
        h0 = torch.zeros(self.num_layers * 2, x.size(0), self.hidden_dim).to(x.device)
        c0 = torch.zeros(self.num_layers * 2, x.size(0), self.hidden_dim).to(x.device)
        
        # Forward propagate LSTM
        out, _ = self.lstm(x, (h0, c0))
        
        # Decode the hidden state of the last time step
        out = self.dropout(out[:, -1, :])
        out = self.fc(out)
        return out


class BiLSTMInterface:
    """Wrapper to handle the BiLSTM loading/predicting logic easily"""
    def __init__(self, model_path="ml/models/bilstm_model.pt"):
        self.model_path = model_path
        self.model = BehaviouralBiLSTM()
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        self.classes = ["SCRIPT_BOT", "PERSISTENT_ATTACKER", "APT"]
        
        if os.path.exists(self.model_path):
            self.model.load_state_dict(torch.load(self.model_path, map_location=self.device, weights_only=True))
            self.model.eval()
            self._trained = True
        else:
            self._trained = False
            
    def predict(self, feature_sequence):
        if not self._trained:
            # Fallback behavior
            return "UNKNOWN (Needs Training)"
            
        with torch.no_grad():
            tensor_seq = torch.FloatTensor(feature_sequence).unsqueeze(0).to(self.device)
            outputs = self.model(tensor_seq)
            _, predicted = torch.max(outputs.data, 1)
            return self.classes[predicted.item()]
