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

#column definitions

NSL_KDD_COLS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "extra_col_1","extra_col_2",
    "label",
    "difficulty"
]


NSL_CATEGORICAL = ["protocol_type", "service", "flag"]

NSL_CATEGORIES = {
    "protocol_type": ["tcp", "udp", "icmp"],
    "service": [
        "aol","auth","bgp","courier","csnet_ns","ctf","daytime","discard",
        "domain","domain_u","echo","eco_i","ecr_i","efs","exec","finger",
        "ftp","ftp_data","gopher","harvest","hostnames","http","http_2784",
        "http_443","http_8001","imap4","IRC","iso_tsap","klogin","kshell",
        "ldap","link","login","mtp","name","netbios_dgm","netbios_ns",
        "netbios_ssn","netstat","nnsp","nntp","ntp_u","other","pm_dump",
        "pop_2","pop_3","printer","private","red_i","remote_job","rje",
        "shell","smtp","sql_net","ssh","sunrpc","supdup","systat","telnet",
        "tftp_u","tim_i","time","urh_i","urp_i","uucp","uucp_path",
        "vmnet","whois","X11","Z39_50"
    ],
    "flag": ["SF","S0","REJ","RSTR","RSTO","SH","S1","S2","S3","OTH"]
}

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

NSL_LABEL_MAP = {
    0: "normal",
    1: "neptune",
    2: "smurf",
    3: "guess_passwd",
    4: "buffer_overflow",
    5: "imap",
    6: "warezclient",
    7: "warezmaster",
    8: "portsweep",
    9: "satan",
    10: "ipsweep",
    11: "ftp_write",
    12: "multihop",
    13: "phf",
    14: "spy",
    15: "pod",
    16: "land",
    17: "loadmodule",
    18: "rootkit",
    19: "mailbomb",
    20: "apache2",
    21: "processtable",
    22: "udpstorm",
    23: "perl",
    24: "xterm",
    25: "ps",
    26: "httptunnel",
    27: "worm",
    28: "snmpguess",
    29: "snmpgetattack",
    30: "xsnoop",
    31: "xlock",
    32: "mscan",
    33: "saint",
    34: "back",
    35: "teardrop",
    36: "sendmail",
    37: "named"
}



class Preprocessor:
    def __init__(self, dataset_type="cic"):
        self.dataset_type = dataset_type
        self.ct = None
        self.label_encoder = LabelEncoder()
        self.feature_names = []

    #Build ColumnTransformer
    def _build_ct(self, numeric_cols, categorical_cols):
        num_pipe = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler())
        ])

        if self.dataset_type == "nsl":
            cat_pipe = Pipeline([
                ("imputer", SimpleImputer(strategy="most_frequent")),
                ("onehot", OneHotEncoder(
                    categories = [NSL_CATEGORIES[col] for col in categorical_cols],
                    handle_unknown="ignore",
                    sparse_output=False
                ))
            ])
        else:
            cat_pipe = Pipeline([
                ("imputer", SimpleImputer(strategy="most_frequent")),
                ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False))
            ])

        return ColumnTransformer([
            ("num", num_pipe, numeric_cols),
            ("cat", cat_pipe, categorical_cols)
        ])
    
    def _prepare_dataframe(self, path:str):
        df = pd.read_csv(path, header=None if self.dataset_type == "nsl" else 0)
        if self.dataset_type == "nsl":
            actual = df.shape[1]
            expected = len(NSL_KDD_COLS)
            
            if actual != expected:
                print(f"[!] Warning: Expected {expected}, got {actual}. Adjusting..")
            
            df.columns = NSL_KDD_COLS[:actual]
        
        return df
    
    def fit_transform(self, df: pd.DataFrame):
        df = df.copy()

        def clean_label(lbl):
            "Normalize label strings by removing  weird characters"
            if isinstance(lbl, str):
                return lbl.encode("ascii", errors="ignore").decode()
            return lbl

        if self.dataset_type == "cic":
            df.columns = df.columns.str.strip()

            label_col = None
            for cand in ["Label", "label", " Label"]:
                if cand in df.columns:
                    label_col = cand
                    break
            
            if label_col is None:
                print("[WARNING] No label column found in CIC file")
                return None, None
            
            X = df.drop(columns=[label_col])
            y_raw = df[label_col].values

            y = []
            for lbl in y_raw:
                try:
                    lbl_int = int(lbl)
                    y.append(CIC_LABEL_MAP.get(lbl_int, clean_label(lbl)))
                except ValueError:
                    y.append(str(lbl).strip())
            
            numeric_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
            categorical_cols = [c for c in X.columns if c not in numeric_cols]

        elif self.dataset_type == "nsl":
            X = df.drop(columns=["label", "difficulty"], errors="ignore")
            y_raw = df["label"].values if "label" in df.columns else None
            
            categorical_cols = [c for c in NSL_CATEGORICAL if c in X.columns]
            numeric_cols = [c for c in X.columns if c not in categorical_cols]

            y = []
            if y_raw is not None:
                for lbl in y_raw:
                    try:
                        lbl_int = int(lbl)
                        y.append(NSL_LABEL_MAP.get(lbl_int, clean_label(lbl)))
                    except ValueError:
                        y.append(str(lbl).strip())
        else:
            raise ValueError("Unknown dataset type. Use 'cic' or 'nsl'.")     

        X = X.replace([np.inf, -np.inf], np.nan) #turn infinitites to be handled as NaN

        self.ct = self._build_ct(numeric_cols, categorical_cols)    
        X_transformed = self.ct.fit_transform(X)   

        try:
            self.feature_names = self.ct.get_feature_names_out().tolist()
        except:
            self.feature_names = numeric_cols + categorical_cols
        
        y_encoded = self.label_encoder.fit_transform(y) if y is not None else None
        self.original_labels = y.copy() if y is not None else None

        return X_transformed, y_encoded
    
    def load_and_preprocess(self, path: str):
        df = self._prepare_dataframe(path)
        return self.fit_transform(df)
    
    def save_preprocessed(self, X, y, output_dir: str, file_prefix: str):
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        np.save(os.path.join(output_dir, f"{file_prefix}_X.npy"), X)
        np.save(os.path.join(output_dir, f"{file_prefix}_y.npy"), y)

        meta = {"feature_names": self.feature_names}
        if hasattr(self, "original_labels") and self.original_labels is not None:
            meta["label_classes"] = self.label_encoder.classes_.tolist()
        else:
            meta["label_classes"] = None
            
        joblib.dump(meta, os.path.join(output_dir, f"{file_prefix}_meta.pkl"))

#process single line
def preprocess_and_save(input_path: str, dataset_type: str, output_root="data/preprocessed"):
    file_name = Path(input_path).stem
    output_dir = os.path.join(output_root, dataset_type)
    prep = Preprocessor(dataset_type=dataset_type)
    X, y = prep.load_and_preprocess(input_path)
    prep.save_preprocessed(X, y, output_dir, file_name)

    return X,y

#process all files in a dataset
def batch_preprocess(raw_root="data/raw", output_root="data/preprocessed"):
    merged_data = {"cic": [], "nsl": []}
    merged_labels = {"cic": [], "nsl": []}

    feature_names_map = {"cic": None, "nsl": None}

    # --- CIC-IDS2017 preprocessing ---
    cic_dir = Path(raw_root) / "cic-ids2017"
    
    if cic_dir.exists():
        all_cic_cols = set()
        cic_files = list(cic_dir.glob("*.csv"))
        
        # Get all unique columns from all files
        for file in cic_files:
            df_head = pd.read_csv(file, nrows=0)
            all_cic_cols.update(df_head.columns.tolist())
        
        all_cic_cols = sorted(list(all_cic_cols))
        
        for file in cic_files:
            prep = Preprocessor(dataset_type="cic")
            df = pd.read_csv(file)
            
            for col in all_cic_cols:
                if col not in df.columns:
                    df[col] = 0
            
            df = df[all_cic_cols]
            
            X, y = prep.fit_transform(df)
            feature_names_map["cic"] = prep.feature_names

            if y is None:
                print(f"[WARNING] Skipping {file.name} (no labels found)")
                continue

            prep.save_preprocessed(X, y, os.path.join(output_root, "cic"), Path(file).stem)
            print(f"[DEBUG] File {file.name} -> aligned shape {X.shape}")
            merged_data["cic"].append(X)
            merged_labels["cic"].append(y)

    # --- NSL-KDD preprocessing ---
    nsl_dir = Path(raw_root) / "nsl-kdd"
    if nsl_dir.exists():
        prep = Preprocessor(dataset_type="nsl")
        for file in nsl_dir.glob("*.txt"):
            X, y = prep.load_and_preprocess(str(file))
            feature_names_map["nsl"] = prep.feature_names
            prep.save_preprocessed(X, y, os.path.join(output_root, "nsl"), Path(file).stem)
            print(f"[DEBUG] File {file.name} -> shape {X.shape}")
            merged_data["nsl"].append(X)
            merged_labels["nsl"].append(y)

    # --- Merge and save datasets ---
    for dtype in ["cic", "nsl"]:
        if merged_data[dtype]:
            feature_counts = [arr.shape[1] for arr in merged_data[dtype]]
            if len(set(feature_counts)) > 1:
                print(f"[WARNING] {dtype.upper()} files have different feature counts: {feature_counts}")
                
                max_features = max(feature_counts)
                padded_arrays = []
                for arr in merged_data[dtype]:
                    if arr.shape[1] < max_features:
                        pad_width = max_features - arr.shape[1]
                        padded_arr = np.pad(arr, ((0, 0), (0, pad_width)), mode='constant')
                        padded_arrays.append(padded_arr)
                    else:
                        padded_arrays.append(arr)
                
                X_all = np.vstack(padded_arrays)
            else:
                X_all = np.vstack(merged_data[dtype])
            
            y_all = np.hstack(merged_labels[dtype])

            outdir = Path(output_root) / dtype
            outdir.mkdir(parents=True, exist_ok=True)
            np.save(outdir / f"{dtype}_ALL_X.npy", X_all)
            np.save(outdir / f"{dtype}_ALL_y.npy", y_all)

            le = LabelEncoder().fit(y_all)

            meta =  {
                "feature_names": feature_names_map[dtype],
                "label_classes": le.classes_.tolist()
            }
            joblib.dump(meta, outdir / f"{dtype}_ALL_meta.pkl")

            print(f"[+] Saved merged {dtype.upper()} dataset with shape {X_all.shape}")

if __name__ == "__main__":
    batch_preprocess()