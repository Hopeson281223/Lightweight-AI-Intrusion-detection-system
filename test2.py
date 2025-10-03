from pathlib import Path
import numpy as np
import joblib

def check_labels(preprocessed_root="data/preprocessed"):
    datasets = ["cic", "nsl"]

    for ds in datasets:
        ds_dir = Path(preprocessed_root) / ds
        if not ds_dir.exists():
            print(f"[WARNING] {ds_dir} does not exist. Skipping.")
            continue

        print(f"\n=== Checking {ds.upper()} dataset ===")

        all_labels = set()
        meta_files = list(ds_dir.glob("*_meta.pkl"))
        
        for meta_file in meta_files:
            meta = joblib.load(meta_file)
            labels = meta.get("label_classes", [])
            if labels is not None:
                all_labels.update(labels)

        # Convert all labels to strings for consistent sorting
        all_labels_str = [str(l) for l in all_labels]
        print(f"[INFO] Found labels in {ds.upper()}: {sorted(all_labels_str)}")


if __name__ == "__main__":
    check_labels()
