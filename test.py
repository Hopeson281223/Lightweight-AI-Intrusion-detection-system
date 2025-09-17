import numpy as np
from pathlib import Path

X = np.load("data/preprocessed/cic/cic_ALL_X.npy", allow_pickle=True)
y = np.load("data/preprocessed/cic/cic_ALL_y.npy", allow_pickle=True)

print("X shape:", X.shape)
print("y shape:", y.shape)
print("Unique labels in y:", np.unique(y)[:20])  # first 20 classes if many
