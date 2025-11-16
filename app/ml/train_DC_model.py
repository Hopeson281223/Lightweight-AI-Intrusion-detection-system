from pathlib import Path
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
import joblib
from collections import Counter
from datetime import datetime

# Import your database functions
from app.storage.db import save_metrics, save_model_info

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
    """Train a lightweight Decision Tree classifier with class balancing."""
    clf = DecisionTreeClassifier(
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        class_weight="balanced",  
        random_state=42
    )
    clf.fit(X_train, y_train)
    return clf

def evaluate_model(clf, X_test, y_test):
    """Evaluate model accuracy and generate a classification report."""
    y_pred = clf.predict(X_test)
    
    # Calculate multiple metrics
    acc = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    
    report = classification_report(y_test, y_pred)
    print(f"\n Accuracy: {acc:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-Score: {f1:.4f}")
    print(f"Classification Report:\n{report}")
    
    return {
        'accuracy': acc,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'classification_report': report
    }

def save_model(clf, model_path):
    """Save trained model to file."""
    joblib.dump(clf, model_path)
    print(f" Model saved at: {model_path}")
    return model_path

def save_training_metrics(model_name, dataset_name, metrics, model_size_kb, feature_count, training_time):
    """Save training metrics to database."""
    try:
        # Save individual metrics
        save_metrics(f"model_{model_name}_accuracy", f"{metrics['accuracy']:.4f}")
        save_metrics(f"model_{model_name}_precision", f"{metrics['precision']:.4f}")
        save_metrics(f"model_{model_name}_recall", f"{metrics['recall']:.4f}")
        save_metrics(f"model_{model_name}_f1_score", f"{metrics['f1_score']:.4f}")
        save_metrics(f"model_{model_name}_size_kb", f"{model_size_kb:.2f}")
        save_metrics(f"model_{model_name}_feature_count", feature_count)
        save_metrics(f"model_{model_name}_training_time_seconds", f"{training_time:.2f}")
        save_metrics(f"model_{model_name}_dataset", dataset_name)
        save_metrics(f"model_{model_name}_trained_at", datetime.now().isoformat())
        
        print(f"✅ Training metrics saved to database for {model_name}")
        return True
    except Exception as e:
        print(f"❌ Error saving training metrics: {e}")
        return False

def main():
    training_start_time = datetime.now()
    print("[INFO] Loading preprocessed CIC dataset...")
    X, y = load_dataset(DATASET["X"], DATASET["y"])

    print(f"[INFO] Dataset shape: {X.shape}, Unique labels: {len(np.unique(y))}")
    print("[INFO] Label distribution:", Counter(y))

    X_train, X_test, y_train, y_test = split_data(X, y)
    print(f"[INFO] Train shape: {X_train.shape}, Test shape: {X_test.shape}")

    # Train model
    clf = train_lightweight_decision_tree(X_train, y_train)
    model_path = save_model(clf, MODEL_DIR / DATASET["model_name"])

    # Evaluate model
    metrics = evaluate_model(clf, X_test, y_test)

    # Load meta info
    try:
        meta = joblib.load(DATASET["meta"])
        feature_names = meta.get("feature_names", [])
        label_classes = meta.get("label_classes", [])
        print(f"[INFO] Loaded meta info: {len(feature_names)} features, {len(label_classes)} label classes.")
    except:
        feature_names, label_classes = [], []
        print("[WARNING] No meta file found.")

    # Calculate model size and training time
    model_size_kb = (MODEL_DIR / DATASET["model_name"]).stat().st_size / 1024
    training_time = (datetime.now() - training_start_time).total_seconds()

    # Save model info to database
    try:
        save_model_info(
            name=DATASET["model_name"],
            dataset="cic",
            path=str(model_path),
            size_kb=model_size_kb,
            feature_names=feature_names,
            label_classes=label_classes
        )
        print("Model info saved to database")
    except Exception as e:
        print(f"Error saving model info: {e}")

    # Save training metrics to database
    save_training_metrics(
        model_name=DATASET["model_name"],
        dataset_name="cic",
        metrics=metrics,
        model_size_kb=model_size_kb,
        feature_count=len(feature_names) if feature_names else X.shape[1],
        training_time=training_time
    )

    print("\nTraining complete!")
    print(f"Model path: {MODEL_DIR / DATASET['model_name']}")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall: {metrics['recall']:.4f}")
    print(f"F1-Score: {metrics['f1_score']:.4f}")
    print(f"Model size: {model_size_kb:.2f} KB")
    print(f"Training time: {training_time:.2f} seconds")
    print(f"Features: {len(feature_names) if feature_names else X.shape[1]}")
    print("All metrics saved to database!")

if __name__ == "__main__":
    main()