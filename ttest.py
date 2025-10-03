import numpy as np
from pathlib import Path

def check_unmapped_labels(preprocessed_root="data/preprocessed", dataset="cic"):
    ds_dir = Path(preprocessed_root) / dataset
    for npy_file in ds_dir.glob("*_y.npy"):
        y = np.load(npy_file)
        unmapped = [lbl for lbl in y if str(lbl).isdigit()]
        if unmapped:
            print(f"{npy_file.name} has numeric/unmapped labels: {set(unmapped)}")

check_unmapped_labels(dataset="cic")
check_unmapped_labels(dataset="nsl")
