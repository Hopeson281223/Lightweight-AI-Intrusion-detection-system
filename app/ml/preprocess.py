from __future__ import annotations
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
import joblib
import os

CIC_LABEL_MAP = {
    0: "BENIGN",
    1: "DoS Hulk",
    2: "DoS GoldenEye",
    3: "DoS Slowloris",
    4: "DoS Slowhttptest",
    5: "DDoS",
    6: "Bot",
    7: "Web Attack – Brute Force",
    8: "Web Attack – XSS",
    9: "Web Attack – SQL Injection",
    10: "FTP-Patator",
    11: "SSH-Patator",
    12: "Infiltration",
    13: "Heartbleed",
}

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
    "Label"
]


class Preprocessor:
    def __init__(self):
        self.ct = None
        self.label_encoder = LabelEncoder()
        self.feature_names = []

    #Build ColumnTransformer
    def _build_ct(self, numeric_cols, categorical_cols):
        num_pipe = Pipeline([
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler())
        ])

        cat_pipe = Pipeline([
            ('imputer', SimpleImputer(strategy='most_frequent')),
            ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
        ])

        return ColumnTransformer([
            ('num', num_pipe, numeric_cols),
            ('cat', cat_pipe, categorical_cols)
        ])
        
    def fit_transform(self, df: pd.DataFrame):
        df = df.copy()
        df.columns = df.columns.str.strip()

        label_col = next((c for c in df.columns if "label" in c.lower()), None)
        if label_col is None:
            print("[WARNING] No label column found in CIC file")
            return None, None

    
        y_raw = df[label_col].values
        X = df.drop(columns=[label_col])

        available_features = [c for c in LIVE_FEATURES if c in X.columns]
        X = X[available_features]

        def clean_label(lbl):
            if isinstance(lbl, str):
                return lbl.encode("ascii", errors="ignore").decode().strip()
            return str(lbl)
        
        y = []
        for lbl in y_raw:
            try:
                lbl_int = int(lbl)
                label_str = CIC_LABEL_MAP.get(lbl_int, clean_label(lbl))
            except ValueError:
                label_str = str(lbl).strip()
                 
            if "BENIGN" in label_str.upper():
                y.append("NORMAL")
            else:
                y.append("ANOMALOUS")
        
        numeric_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
        categorical_cols = [c for c in X.columns if c not in numeric_cols]

        X = X.replace([np.inf, -np.inf], np.nan) #turn infinitites to be handled as NaN

        self.ct = self._build_ct(numeric_cols, categorical_cols)    
        X_transformed = self.ct.fit_transform(X)   
        self.feature_names = self.ct.get_feature_names_out().tolist()
        y_encoded = self.label_encoder.fit_transform(y)
        self.original_labels = y.copy()

        return X_transformed, y_encoded
    
    def save_preprocessed(self, X, y, output_dir: str, file_prefix: str):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        np.save(os.path.join(output_dir, f"{file_prefix}_X.npy"), X)
        np.save(os.path.join(output_dir, f"{file_prefix}_y.npy"), y)

        meta = {
            "feature_names": self.feature_names,
            "label_classes": self.label_encoder.classes_.tolist()
        }         
        joblib.dump(meta, os.path.join(output_dir, f"{file_prefix}_meta.pkl"))

#process all files in a dataset
def batch_preprocess(raw_root="data/raw/cic-ids2017", output_root="data/preprocessed/cic"):
    """Preprocess all CIC-IDS2017 files using only live-detectable features."""
    merged_data, merged_labels = [], []
    feature_names = None

    cic_dir = Path(raw_root)
    if not cic_dir.exists():
        print(f"[ERROR] Directory not found: {cic_dir}")
        return

    cic_files = list(cic_dir.glob("*.csv"))
    for file in cic_files:
        print(f"[INFO] Processing {file.name} ...")
        df = pd.read_csv(file)
        prep = Preprocessor()
        X, y = prep.fit_transform(df)
        if X is None or y is None:
            continue

        feature_names = prep.feature_names
        prep.save_preprocessed(X, y, output_root, Path(file).stem)
        merged_data.append(X)
        merged_labels.append(y)

    if merged_data:
        X_all = np.vstack(merged_data)
        y_all = np.hstack(merged_labels)

        np.save(Path(output_root) / "CIC_ALL_X.npy", X_all)
        np.save(Path(output_root) / "CIC_ALL_y.npy", y_all)

        joblib.dump({
            "feature_names": feature_names,
            "label_classes": prep.label_encoder.classes_.tolist()
        }, Path(output_root) / "CIC_ALL_meta.pkl")

        print(f"[+] Saved merged CIC dataset with shape {X_all.shape}")


if __name__ == "__main__":
    batch_preprocess()