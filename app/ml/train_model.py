from pathlib import Path
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
from storage.db import get_db, init_db, save_metrics, save_model_info
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