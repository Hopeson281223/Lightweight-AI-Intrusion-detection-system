import numpy as np
import pandas as pd
import joblib
import os

# === Load your trained model ===
MODEL_PATH = "models/decision_tree_cic_model.joblib"

print(f"[INFO] Loading model from: {MODEL_PATH}")
model_data = joblib.load(MODEL_PATH)

if isinstance(model_data, tuple):
    model, feature_names = model_data
else:
    model = model_data
    feature_names = None

print("[INFO] Model loaded successfully.")

# === Features expected by model ===
LIVE_FEATURES = [
    "Destination Port", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count",
    "Average Packet Size", "Fwd Header Length", "Bwd Header Length",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance",
    "Down/Up Ratio", "Subflow Fwd Packets", "Subflow Bwd Packets",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
]

# === Generate synthetic flows ===
np.random.seed(42)
n_samples = 10

df = pd.DataFrame({
    "Destination Port": np.random.choice([20, 21, 22, 23, 25, 53, 80, 110, 443, 8080, 3306, 3389, 9999], n_samples),
    "Flow Duration": np.random.uniform(0.001, 200.0, n_samples),
    "Total Fwd Packets": np.random.randint(1, 5000, n_samples),
    "Total Backward Packets": np.random.randint(1, 5000, n_samples),
    "Total Length of Fwd Packets": np.random.uniform(100.0, 1e6, n_samples),
    "Total Length of Bwd Packets": np.random.uniform(100.0, 1e6, n_samples),
    "Fwd Packet Length Max": np.random.uniform(40.0, 1500.0, n_samples),
    "Fwd Packet Length Min": np.random.uniform(0.0, 300.0, n_samples),
    "Fwd Packet Length Mean": np.random.uniform(50.0, 800.0, n_samples),
    "Fwd Packet Length Std": np.random.uniform(5.0, 300.0, n_samples),
    "Bwd Packet Length Max": np.random.uniform(40.0, 1500.0, n_samples),
    "Bwd Packet Length Min": np.random.uniform(0.0, 300.0, n_samples),
    "Bwd Packet Length Mean": np.random.uniform(50.0, 800.0, n_samples),
    "Bwd Packet Length Std": np.random.uniform(5.0, 300.0, n_samples),
    "Flow Bytes/s": np.random.uniform(1.0, 1e6, n_samples),
    "Flow Packets/s": np.random.uniform(0.1, 10000.0, n_samples),
    "Flow IAT Mean": np.random.uniform(0.0, 200.0, n_samples),
    "Flow IAT Std": np.random.uniform(0.0, 100.0, n_samples),
    "Flow IAT Max": np.random.uniform(0.0, 500.0, n_samples),
    "Flow IAT Min": np.random.uniform(0.0, 10.0, n_samples),
    "Fwd PSH Flags": np.random.randint(0, 2, n_samples),
    "Bwd PSH Flags": np.random.randint(0, 2, n_samples),
    "Fwd URG Flags": np.random.randint(0, 2, n_samples),
    "Bwd URG Flags": np.random.randint(0, 2, n_samples),
    "FIN Flag Count": np.random.randint(0, 2, n_samples),
    "SYN Flag Count": np.random.randint(0, 2, n_samples),
    "RST Flag Count": np.random.randint(0, 2, n_samples),
    "PSH Flag Count": np.random.randint(0, 2, n_samples),
    "ACK Flag Count": np.random.randint(0, 2, n_samples),
    "URG Flag Count": np.random.randint(0, 2, n_samples),
    "CWE Flag Count": np.random.randint(0, 2, n_samples),
    "ECE Flag Count": np.random.randint(0, 2, n_samples),
    "Average Packet Size": np.random.uniform(50.0, 1500.0, n_samples),
    "Fwd Header Length": np.random.uniform(5.0, 50.0, n_samples),
    "Bwd Header Length": np.random.uniform(5.0, 50.0, n_samples),
    "Min Packet Length": np.random.uniform(20.0, 60.0, n_samples),
    "Max Packet Length": np.random.uniform(500.0, 1500.0, n_samples),
    "Packet Length Mean": np.random.uniform(200.0, 800.0, n_samples),
    "Packet Length Std": np.random.uniform(10.0, 300.0, n_samples),
    "Packet Length Variance": np.random.uniform(100.0, 90000.0, n_samples),
    "Down/Up Ratio": np.random.uniform(0.1, 5.0, n_samples),
    "Subflow Fwd Packets": np.random.randint(1, 1000, n_samples),
    "Subflow Bwd Packets": np.random.randint(1, 1000, n_samples),
    "Init_Win_bytes_forward": np.random.randint(1, 65535, n_samples),
    "Init_Win_bytes_backward": np.random.randint(1, 65535, n_samples),
    "act_data_pkt_fwd": np.random.randint(0, 1000, n_samples),
})

# Fill missing columns if model expects others
for col in LIVE_FEATURES:
    if col not in df.columns:
        df[col] = 0

# Keep only features the model needs
X = df[[col for col in LIVE_FEATURES if col != "Label"]]

print(f"[INFO] Generated {len(X)} synthetic flows with {X.shape[1]} features.")

# === Predict ===
preds = model.predict(X)
df["Prediction"] = np.where(preds == 0, "NORMAL", "ANOMALOUS")

# === Save results ===
OUTPUT_FILE = "simulated_full_predictions.csv"
df.to_csv(OUTPUT_FILE, index=False)

print(f"[SUCCESS] Predictions saved to {OUTPUT_FILE}")
print(df[["Destination Port", "Flow Duration", "Flow Bytes/s", "Prediction"]])
