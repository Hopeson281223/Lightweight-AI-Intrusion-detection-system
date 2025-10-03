import joblib
from pathlib import Path

# Paths to your meta files
PREPROCESSED_DIR = Path("data/preprocessed")

def show_labels(dataset: str):
    meta_path = PREPROCESSED_DIR / dataset / f"{dataset}_ALL_meta.pkl"
    if not meta_path.exists():
        print(f"⚠️ No meta file found for {dataset}")
        return
    
    meta = joblib.load(meta_path)
    if "label_classes" in meta:
        print(f"✅ {dataset.upper()} labels:")
        for i, label in enumerate(meta["label_classes"]):
            print(f"  {i}: {label}")
    else:
        print(f"⚠️ No label_classes found in {dataset}_ALL_meta.pkl")

# Test for both
show_labels("nsl")
show_labels("cic")
