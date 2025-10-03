from pathlib import Path
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
from app.storage.db import get_db, init_db, save_metrics, save_model_info
from datetime import datetime

PREPROCESSED_DIR = Path("data/preprocessed")
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(parents=True, exist_ok=True)

DATASETS = {
    "cic" : {
        "X" : PREPROCESSED_DIR / "cic" / "cic_ALL_X.npy",
        "y" : PREPROCESSED_DIR / "cic" / "cic_ALL_y.npy",
        "model_name": "decision_tree_cic_model.joblib"
    }, 
    "nsl" : {
        "X" : PREPROCESSED_DIR / "nsl" / "nsl_ALL_X.npy",
        "y" : PREPROCESSED_DIR / "nsl" / "nsl_ALL_y.npy",
        "model_name": "decision_tree_nsl_model.joblib"
    }
}

def load_dataset(X_path, y_path):
    X = np.load(X_path, allow_pickle=True)
    y = np.load(y_path, allow_pickle=True)

    X = np.array(X, dtype=np.float32)

    return X, y

def split_data(X, y, test_size=0.2, random_state=42):
    return train_test_split(X, y, test_size=test_size, random_state=random_state, stratify=y)

def train_lightweight_decision_tree(X_train, y_train, max_depth=10, min_samples_split=20):
    clf = DecisionTreeClassifier(
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        random_state=42
    )
    clf.fit(X_train, y_train)
    return clf

def save_model(clf, path):
    joblib.dump(clf, path)

def evaluate_and_save(clf, X_test, y_test, model_label):
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred)

    print(f"[INFO] Accuracy ({model_label}) {acc:.4f}")
    print(f"[INFO] Classification Report ({model_label}):\n{report}")

    save_metrics(f"{model_label}_accuracy", acc)
    save_metrics(f"{model_label}_classification_report", report)

    return acc, report

def main():
    init_db()

    for dataset_key, dataset_info in DATASETS.items():
        print(f"\n[INFO] Processing dataset: {dataset_key.upper()}")

        X, y = load_dataset(dataset_info["X"], dataset_info["y"])
        X_train, X_test, y_train, y_test = split_data(X, y)
        print(f"[INFO] {dataset_key.upper()} shapes -> Train: {X_train.shape}, Test: {X_test.shape}")

        clf = train_lightweight_decision_tree(X_train, y_train)

        model_path = MODEL_DIR / dataset_info["model_name"]
        save_model(clf, model_path)
        print(f"[INFO] Model saved at: {model_path}")

        evaluate_and_save(clf, X_test, y_test, dataset_key)

        model_size_kb = model_path.stat().st_size / 1024
        print(f"[INFO] Model size ({dataset_key}): {model_size_kb:.2f} KB")
        save_metrics(f"{dataset_key}_model_size_kb", model_size_kb)

        try:
            meta_path = Path("data/preprocessed") / dataset_key / f"{dataset_key}_ALL_meta.pkl"
            meta = joblib.load(meta_path)
            feature_names = meta.get("feature_names", None)
            label_classes = meta.get("label_classes", None)
        except:
            feature_names = None
            label_classes = None

        save_model_info(
            name=dataset_info["model_name"],
            dataset=dataset_key,
            path=model_path,
            size_kb=model_size_kb,
            feature_names=feature_names,
            label_classes=label_classes
        )
        print(f"[INFO] Model info ({dataset_key}) saved to DB")

if __name__ == "__main__":
    main()