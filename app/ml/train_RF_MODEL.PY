from pathlib import Path
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
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
    "model_name": "random_forest_cic_model.joblib"
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

def train_random_forest(X_train, y_train, n_estimators=100, max_depth=15, min_samples_split=10, n_jobs=-1):
    """Train a Random Forest classifier with optimized parameters for intrusion detection."""
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_split=min_samples_split,
        class_weight="balanced",
        n_jobs=n_jobs,  # Use all available cores
        random_state=42,
        bootstrap=True,
        oob_score=True  # Out-of-bag score for additional validation
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
    
    # Random Forest specific metrics
    if hasattr(clf, 'oob_score_'):
        print(f"OOB Score: {clf.oob_score_:.4f}")
    
    print(f"Classification Report:\n{report}")
    
    metrics_dict = {
        'accuracy': acc,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'classification_report': report
    }
    
    # Add OOB score if available
    if hasattr(clf, 'oob_score_'):
        metrics_dict['oob_score'] = clf.oob_score_
    
    return metrics_dict

def save_model(clf, model_path):
    """Save trained model to file."""
    joblib.dump(clf, model_path)
    print(f" Model saved at: {model_path}")
    return model_path

def save_training_metrics(model_name, dataset_name, metrics, model_size_kb, feature_count, training_time, model_params=None):
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
        save_metrics(f"model_{model_name}_model_type", "random_forest")
        
        # Save OOB score if available
        if 'oob_score' in metrics:
            save_metrics(f"model_{model_name}_oob_score", f"{metrics['oob_score']:.4f}")
        
        # Save model parameters
        if model_params:
            save_metrics(f"model_{model_name}_n_estimators", model_params.get('n_estimators', 100))
            save_metrics(f"model_{model_name}_max_depth", model_params.get('max_depth', 15))
        
        print(f"✅ Training metrics saved to database for {model_name}")
        return True
    except Exception as e:
        print(f"❌ Error saving training metrics: {e}")
        return False

def feature_importance_analysis(clf, feature_names=None):
    """Analyze and display feature importance."""
    importances = clf.feature_importances_
    
    if feature_names and len(feature_names) == len(importances):
        # Create feature importance dictionary
        feature_imp = list(zip(feature_names, importances))
        # Sort by importance
        feature_imp.sort(key=lambda x: x[1], reverse=True)
        
        print("\n🔍 Top 10 Most Important Features:")
        for i, (feature, importance) in enumerate(feature_imp[:10]):
            print(f"  {i+1}. {feature}: {importance:.4f}")
            
        return feature_imp
    else:
        print(f"\n📊 Feature Importance (Top 10):")
        indices = np.argsort(importances)[::-1][:10]
        for i, idx in enumerate(indices):
            print(f"  {i+1}. Feature {idx}: {importances[idx]:.4f}")
        return None

def main():
    training_start_time = datetime.now()
    print("[INFO] Loading preprocessed CIC dataset for Random Forest training...")
    X, y = load_dataset(DATASET["X"], DATASET["y"])

    print(f"[INFO] Dataset shape: {X.shape}, Unique labels: {len(np.unique(y))}")
    print("[INFO] Label distribution:", Counter(y))

    X_train, X_test, y_train, y_test = split_data(X, y)
    print(f"[INFO] Train shape: {X_train.shape}, Test shape: {X_test.shape}")

    # Train Random Forest model
    print("[INFO] Training Random Forest classifier...")
    model_params = {
        'n_estimators': 100,
        'max_depth': 15,
        'min_samples_split': 10
    }
    
    clf = train_random_forest(X_train, y_train, **model_params)

    # Save model
    model_path = save_model(clf, MODEL_DIR / DATASET["model_name"])

    # Evaluate model
    print("[INFO] Evaluating Random Forest model...")
    metrics = evaluate_model(clf, X_test, y_test)

    # Load meta info
    try:
        meta = joblib.load(DATASET["meta"])
        feature_names = meta.get("feature_names", [])
        label_classes = meta.get("label_classes", [])
        print(f"[INFO] Loaded meta info: {len(feature_names)} features, {len(label_classes)} label classes.")
    except Exception as e:
        feature_names, label_classes = [], []
        print(f"[WARNING] No meta file found or error loading: {e}")

    # Feature importance analysis
    feature_importance_analysis(clf, feature_names)

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
            label_classes=label_classes,
            model_type="random_forest"
        )
        print("✅ Model info saved to database")
    except Exception as e:
        print(f"❌ Error saving model info: {e}")

    # Save training metrics to database
    save_training_metrics(
        model_name=DATASET["model_name"],
        dataset_name="cic",
        metrics=metrics,
        model_size_kb=model_size_kb,
        feature_count=len(feature_names) if feature_names else X.shape[1],
        training_time=training_time,
        model_params=model_params
    )

    print("\n🎯 Random Forest Training Complete!")
    print(f"Model path: {MODEL_DIR / DATASET['model_name']}")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall: {metrics['recall']:.4f}")
    print(f"F1-Score: {metrics['f1_score']:.4f}")
    if 'oob_score' in metrics:
        print(f"OOB Score: {metrics['oob_score']:.4f}")
    print(f"Model size: {model_size_kb:.2f} KB")
    print(f"Training time: {training_time:.2f} seconds")
    print(f"Features: {len(feature_names) if feature_names else X.shape[1]}")
    print(f"Number of trees: {model_params['n_estimators']}")
    print("📊 All metrics saved to database!")

if __name__ == "__main__":
    main()