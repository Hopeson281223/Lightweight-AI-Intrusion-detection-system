import numpy as np

X = np.load("data/preprocessed/nsl/nsl_ALL_X.npy")
y = np.load("data/preprocessed/nsl/nsl_ALL_y.npy")

print("X shape:", X.shape)
print("y shape:", y.shape)
print("Unique labels:", np.unique(y))
