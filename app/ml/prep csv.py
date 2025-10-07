import pandas as pd
import numpy as np
from pathlib import Path

# === CONFIG ===
RAW_ROOT = "data/raw/cic-ids2017"
LIVE_FILE = "data/raw/live_capture.csv"
OUTPUT_CSV = "data/preprocessed/cic/live_features_labeled.csv"

LIVE_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Average Packet Size", "Fwd Header Length", "Bwd Header Length", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "Down/Up Ratio", "Subflow Fwd Packets", "Subflow Bwd Packets",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd"
]

# === LOAD AND MERGE ===
dfs = []

for file in Path(RAW_ROOT).glob("*.csv"):
    df = pd.read_csv(file)
    df.columns = df.columns.str.strip()
    for col in df.columns:
        if "label" in col.lower() and col != "Label":
            df.rename(columns={col: "Label"}, inplace=True)
    dfs.append(df)

live_path = Path(LIVE_FILE)
if live_path.exists():
    live_df = pd.read_csv(live_path)
    live_df.columns = live_df.columns.str.strip()
    if 'label' in live_df.columns and 'Label' not in live_df.columns:
        live_df.rename(columns={'label': 'Label'}, inplace=True)
    dfs.append(live_df)

merged_df = pd.concat(dfs, ignore_index=True, sort=False)

# === MAP LABELS TO NORMAL / ANOMALOUS ===
def map_label(label_value):
    if pd.isna(label_value):
        return "ANOMALOUS"
    label_str = str(label_value).strip()
    if label_str in ["BENIGN", "normal", "0"]:
        return "NORMAL"
    return "ANOMALOUS"

merged_df["Mapped_Label"] = merged_df["Label"].apply(map_label)

# === FILTER FEATURES ===
for col in LIVE_FEATURES:
    if col not in merged_df.columns:
        merged_df[col] = np.nan

final_df = merged_df[LIVE_FEATURES + ["Mapped_Label"]]

# === SAVE CSV ===
Path(OUTPUT_CSV).parent.mkdir(parents=True, exist_ok=True)
final_df.to_csv(OUTPUT_CSV, index=False)
print(f"[+] Saved CSV for all features with labels at: {OUTPUT_CSV}")
