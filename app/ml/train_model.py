from pathlib import Path
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
from datetime import datetime

# Directories
PREPROCESSED_DIR = Path("data/preprocessed/cic")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# Dataset info 
DATASET = {
    "X": PREPROCESSED_DIR / "CIC_ALL_X.npy",
    "y": PREPROCESSED_DIR / "CIC_ALL_y.npy",
    "meta": PREPROCESSED_DIR / "CIC_ALL_meta.pkl",
    "model_name": "decision_tree_cic_model.joblib"
}


def load_dataset(X_path, y_path):
    """Load preprocessed feature and label arrays."""
    X = np.load(X_path, allow_pickle=True)
    y = np.load(y_path, allow_pickle=True)
    X = np.array(X, dtype=np.float32)
    return X, y


def split_data(X, y, test_size=0.2, random_state=42):
    """Split dataset into training and testing sets."""
    return train_test_split(X, y, test_size=test_size, random_state=random_state, stratify=y)


def train_lightweight_decision_tree(X_train, y_train, max_depth=10, min_samples_split=20):
    """Train a lightweight Decision Tree classifier."""
    clf = DecisionTreeClassifier(
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        random_state=42
    )
    clf.fit(X_train, y_train)
    return clf


def evaluate_model(clf, X_test, y_test):
    """Evaluate model accuracy and generate a classification report."""
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred)
    print(f"\n Accuracy: {acc:.4f}")
    print(f"Classification Report:\n{report}")
    return acc, report


def save_model(clf, model_path):
    """Save trained model to file."""
    joblib.dump(clf, model_path)
    print(f" Model saved at: {model_path}")


def main():
    print("[INFO] Loading preprocessed CIC dataset...")
    X, y = load_dataset(DATASET["X"], DATASET["y"])

    print(f"[INFO] Dataset shape: {X.shape}, Labels: {len(np.unique(y))}")

    X_train, X_test, y_train, y_test = split_data(X, y)
    print(f"[INFO] Train shape: {X_train.shape}, Test shape: {X_test.shape}")

    clf = train_lightweight_decision_tree(X_train, y_train)
    save_model(clf, MODEL_DIR / DATASET["model_name"])

    acc, report = evaluate_model(clf, X_test, y_test)

    # Save meta info
    try:
        meta = joblib.load(DATASET["meta"])
        feature_names = meta.get("feature_names", [])
        label_classes = meta.get("label_classes", [])
        print(f"[INFO] Loaded meta info: {len(feature_names)} features, {len(label_classes)} label classes.")
    except:
        feature_names, label_classes = [], []
        print("[WARNING] No meta file found.")

    model_size_kb = (MODEL_DIR / DATASET["model_name"]).stat().st_size / 1024
    print(f"[INFO] Model size: {model_size_kb:.2f} KB")

    print("\n Training complete!")
    print(f"Model path: {MODEL_DIR / DATASET['model_name']}")
    print(f"Accuracy: {acc:.4f}")
    print(f"Model size: {model_size_kb:.2f} KB")


if __name__ == "__main__":
    main()
