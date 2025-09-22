from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.storage.db import init_db, get_db
from pathlib import Path
import joblib
import numpy as np

MODEL_DIR = Path("models")
PREPROCESSED_DIR = Path("data/preprocessed")

#cache for loaded models to prevent loading from disk with every prediction
loaded_models = {}

# create FastAPI app
app = FastAPI(title="LAI-IDS", version="0.1.0")

# Run DB init at startup
@app.on_event("startup")
def startup_event():
    init_db()

class PredictRequest(BaseModel):
    dataset: str
    features: list[float]

def load_model(dataset: str):
    """To load from disk or cache"""
    if dataset in loaded_models:
        return loaded_models[dataset]
    
    model_path = MODEL_DIR / f"decision_tree_{dataset}_model.joblib"
    if not model_path.exists():
        raise HTTPException(status_code=404, detail=f"Model for {dataset} not found")
    
    model = joblib.load(model_path)
    loaded_models[dataset] = model
    return model

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status" : "ok"}

#prediction endpoint
@app.post("/predict")
def predict(req: PredictRequest):
    """Run prediction using chosen dataset model"""
    model = load_model(req.dataset)

    X_input = np.array(req.features).reshape(1, -1)

    try:
        pred = model.predict(X_input)[0]
        prob = model.predict_proba(X_input).max() if hasattr(model, "predict_proba") else None
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Prediction failed: {str(e)}")
    
    return {
        "dataset": req.dataset,
        "prediction": int(pred),
        "confidence": float(prob) if prob is not None else None

    }


#packets endpoint
@app.get("/packets")
def get_packets():
    # to fetch from DB
    return [{"id": 1, "src_ip": "192.168.0.10", "dst_ip": "10.0.0.5", "protocol": "TCP"}]

#metrics endpoint
@app.get("/metrics")
def get_metrics():
    """Return evaluation metrics stored in DB"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name, value, timestamp FROM metrics ORDER BY timestamp DESC")
    rows = cur.fetchall()
    conn.close()

    metrics = [
        {"name": row[0], "value": row[1], "timestamp": row[2]}
        for row in rows
    ]

    return {"metrics": metrics}

#models endpoint
@app.get("/models")
def get_models():
    """Fetch trained models info from DB"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name, dataset, path, size_kb, timestamp FROM models ORDER BY timestamp DESC")
    rows = cur.fetchall()
    conn.close()

    models = [
        {
            "name": row[0],
            "dataset": row[1],
            "path": row[2],
            "size_kb": row[3],
            "timestamp": row[4]
        }
        for row in rows
    ]

    return {"models": models}
