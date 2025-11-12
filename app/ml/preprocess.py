from __future__ import annotations
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
import joblib
from collections import Counter

CIC_LABEL_MAP = {
    0: "BENIGN", 1: "DoS Hulk", 2: "DoS GoldenEye", 3: "DoS Slowloris",
    4: "DoS Slowhttptest", 5: "DDoS", 6: "Bot", 7: "Web Attack – Brute Force",
    8: "Web Attack – XSS", 9: "Web Attack – SQL Injection", 10: "FTP-Patator",
    11: "SSH-Patator", 12: "Infiltration", 13: "Heartbleed",
}

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

class Preprocessor:
    def __init__(self, numeric_cols=None, categorical_cols=None):
        self.ct: ColumnTransformer | None = None
        self.label_encoder = LabelEncoder()
        self.feature_names: list[str] = []
        self.numeric_cols = numeric_cols
        self.categorical_cols = categorical_cols

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

    def _handle_duplicate_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove duplicate columns, keeping only the first occurrence."""
        print(f"[INFO] Original dataset shape: {df.shape}")
        print(f"[INFO] Original columns: {len(df.columns)}")
        
        # Check for duplicate column names
        duplicate_columns = df.columns[df.columns.duplicated()].tolist()
        if duplicate_columns:
            print(f"[WARNING] Found {len(duplicate_columns)} duplicate columns: {duplicate_columns}")
            # Keep only first occurrence of each column
            df = df.loc[:, ~df.columns.duplicated()]
            print(f"[INFO] After removing duplicates - shape: {df.shape}")
        
        return df

    def fit_transform(self, df: pd.DataFrame, y_mapped=None):
        """Modified to accept pre-mapped labels."""
        df = df.copy()
        df.columns = df.columns.str.strip()
        
        # Handle duplicate columns
        df = self._handle_duplicate_columns(df)

        # If y_mapped is provided, use it (for our fixed mapping)
        if y_mapped is not None:
            X = df
            y = y_mapped
        else:
            # Original logic (fallback)
            label_col = next((c for c in df.columns if "label" in c.lower()), None)
            if label_col is None:
                print("[WARNING] No label column found")
                return None, None

            y_raw = df[label_col].values
            X = df.drop(columns=[label_col])
            
            y = []
            for lbl in y_raw:
                label_str = str(lbl).strip()  
                if label_str in ["BENIGN", "normal", "0"]:
                    y.append("NORMAL")
                else:
                    y.append("ANOMALOUS")
        
        available_features = []
        seen_features = set()
        for c in LIVE_FEATURES:
            if c in X.columns and c not in seen_features:
                available_features.append(c)
                seen_features.add(c)
        
        X = X[available_features]
        print(f"[INFO] Using {len(available_features)} unique features from LIVE_FEATURES")

        numeric_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
        categorical_cols = [c for c in X.columns if c not in numeric_cols]

        self.numeric_cols = numeric_cols if self.numeric_cols is None else self.numeric_cols
        self.categorical_cols = categorical_cols if self.categorical_cols is None else self.categorical_cols

        X = X.replace([np.inf, -np.inf], np.nan)

        if self.ct is None:
            self.ct = self._build_ct(self.numeric_cols, self.categorical_cols)

        X_transformed = self.ct.fit_transform(X)
        self.feature_names = self.ct.get_feature_names_out().tolist()
        y_encoded = self.label_encoder.fit_transform(y)
        self.label_encoder.classes_ = np.array(["NORMAL", "ANOMALOUS"])
        self.original_labels = y.copy()
        return X_transformed, y_encoded

    def transform(self, df: pd.DataFrame):
        df = df.copy()
        df.columns = df.columns.str.strip()
        
        # Handle duplicate columns
        df = self._handle_duplicate_columns(df)
        
        available_features = []
        seen_features = set()
        for c in LIVE_FEATURES:
            if c in df.columns and c not in seen_features:
                available_features.append(c)
                seen_features.add(c)
        
        X = df[available_features]
        X = X.replace([np.inf, -np.inf], np.nan)
        return self.ct.transform(X)

    def save_preprocessed(self, X, y, output_dir: str, file_prefix: str):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        np.save(Path(output_dir) / f"{file_prefix}_X.npy", X)
        np.save(Path(output_dir) / f"{file_prefix}_y.npy", y)
        meta = {
            "feature_names": self.feature_names,
            "label_classes": self.label_encoder.classes_.tolist()
        }
        joblib.dump(meta, Path(output_dir) / f"{file_prefix}_meta.pkl")

        joblib.dump(self.ct, Path(output_dir) / f"{file_prefix}_ct.joblib")
        joblib.dump(self.label_encoder, Path(output_dir) / f"{file_prefix}_label_encoder.joblib")


def batch_preprocess(raw_root="data/raw/cic-ids2017", live_file="data/raw/live_capture.csv", output_root="data/preprocessed/cic"):
    """FIXED preprocessing with correct label mapping."""
    dfs = []

    # Load CIC CSVs with column name cleaning
    cic_dir = Path(raw_root)
    if cic_dir.exists():
        for file in cic_dir.glob("*.csv"):
            print(f"[INFO] Loading {file.name}")
            df = pd.read_csv(file)
            df = df.loc[:, ~df.columns.duplicated()]
            
            # Clean column names (remove spaces)
            df.columns = df.columns.str.strip()
            
            # Standardize label column name to 'Label'
            for col in df.columns:
                if 'label' in col.lower():
                    if col != 'Label':
                        print(f"[FIX] Renaming '{col}' to 'Label' in {file.name}")
                        df = df.rename(columns={col: 'Label'})
                    break
            
            dfs.append(df)
    else:
        print(f"[WARNING] CIC directory not found: {cic_dir}")

    # Load live_capture.csv with column name cleaning
    live_path = Path(live_file)
    if live_path.exists():
        print(f"[INFO] Loading live capture {live_path.name}")
        live_df = pd.read_csv(live_path)
        live_df = live_df.loc[:, ~live_df.columns.duplicated()]
        
        # Clean column names
        live_df.columns = live_df.columns.str.strip()
        
        # RENAME the 'label' column to 'Label' to match CIC data
        if 'label' in live_df.columns and 'Label' not in live_df.columns:
            live_df = live_df.rename(columns={'label': 'Label'})
        
        dfs.append(live_df)
    else:
        print(f"[WARNING] live_capture.csv not found: {live_path}")

    if not dfs:
        print("[ERROR] No files to process.")
        return

    # Merge all DataFrames
    merged_df = pd.concat(dfs, ignore_index=True, sort=False)

    print(f"[DEBUG] Merged dataframe columns:")
    all_label_cols = [col for col in merged_df.columns if 'label' in col.lower()]
    print(f"  All label columns: {all_label_cols}")

    # Ensure all LIVE_FEATURES + Label exist
    for col in LIVE_FEATURES + ["Label"]:
        if col not in merged_df.columns:
            merged_df[col] = np.nan

    print(f"[INFO] Merged dataset shape: {merged_df.shape}")

    print("[INFO] Applying FIXED label mapping...")

    print("[DEBUG] Unique labels found in raw data:")
    unique_labels = merged_df['Label'].dropna().unique()
    for label in unique_labels[:20]:  # Show first 20 unique labels
        count = (merged_df['Label'] == label).sum()
        print(f"  '{label}': {count} samples")

    def map_label_correctly(label_value):
        """CORRECT label mapping: BENIGN->NORMAL, live normal->NORMAL, attacks->ANOMALOUS"""
        if pd.isna(label_value):
            return "ANOMALOUS"  # Assumes missing values are anomalous for safety
        
        label_str = str(label_value).strip()  # Keep original case
        
        # Map to NORMAL - BENIGN from CIC and 'normal' from live capture
        if (label_str == "BENIGN" or 
            label_str == "normal" or  
            label_str == "0"):
            return "NORMAL"
        
        # Map to ANOMALOUS - all CIC attack types
        if (label_str == "DDoS" or
            label_str == "PortScan" or 
            label_str == "Bot" or
            label_str == "Infiltration" or
            "Web Attack" in label_str or  # Catches all web attacks
            "Brute Force" in label_str or
            "XSS" in label_str or 
            "Sql" in label_str or
            label_str == "FTP-Patator" or
            label_str == "SSH-Patator" or
            label_str == "DoS GoldenEye" or
            label_str == "DoS Hulk" or
            label_str == "DoS Slowhttptest" or
            label_str == "DoS slowloris" or  # Note lowercase 's'
            label_str == "Heartbleed"):
            return "ANOMALOUS"
        
        # If we don't recognize it, assume it's ANOMALOUS for safety
        return "ANOMALOUS"

    # Apply the corrected mapping
    merged_df['Mapped_Label'] = merged_df['Label'].apply(map_label_correctly)
    
    # Show label distribution
    original_counts = merged_df['Label'].value_counts()
    mapped_counts = merged_df['Mapped_Label'].value_counts()
    
    print("[INFO] Original label distribution:")
    for label, count in original_counts.items():
        print(f"  '{label}': {count} samples")
    
    print("[INFO] Mapped label distribution:")
    for label, count in mapped_counts.items():
        print(f"  {label}: {count} samples")

    # Uses the mapped labels for preprocessing
    label_col = 'Mapped_Label'
    y_raw = merged_df[label_col].values
    X = merged_df.drop(columns=[label_col, 'Label'])  # Remove both label columns
    
    available_features = []
    seen_features = set()
    for c in LIVE_FEATURES:
        if c in X.columns and c not in seen_features:
            available_features.append(c)
            seen_features.add(c)
    
    X = X[available_features]
    print(f"[INFO] Using {len(available_features)} unique features from LIVE_FEATURES")

    y = y_raw  

    # numeric / categorical split
    numeric_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
    categorical_cols = [c for c in X.columns if c not in numeric_cols]

    X = X.replace([np.inf, -np.inf], np.nan)

    prep = Preprocessor()
    prep.numeric_cols = numeric_cols
    prep.categorical_cols = categorical_cols
    prep.ct = prep._build_ct(numeric_cols, categorical_cols)

    X_transformed = prep.ct.fit_transform(X)
    prep.feature_names = prep.ct.get_feature_names_out().tolist()
    
    # Encode the correctly mapped labels
    prep.label_encoder.fit(["NORMAL", "ANOMALOUS"])
    y_encoded = prep.label_encoder.transform(y)
    prep.original_labels = y.copy()
    
    print("[INFO] FINAL class distribution:", Counter(prep.original_labels))
    
    # Save preprocessed data
    prep.save_preprocessed(X_transformed, y_encoded, output_root, "CIC_ALL")
    print(f"[+] Saved FIXED dataset with shape {X_transformed.shape}")

if __name__ == "__main__":
    batch_preprocess()