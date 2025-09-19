from fastapi import FastAPI
from app.storage.db import init_db

# create FastAPI app
app = FastAPI(title="LAI-IDS", version="0.1.0")

# Run DB init at startup
@app.on_event("startup")
def startup_event():
    init_db()

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status" : "ok"}


#prediction endpoint
@app.post("/predict")
def predict(packet: dict):
    # to load mode and run real prediction
    return {"prediction": "normal", "confidence": 0.95}

#packets endpoint
@app.get("/packets")
def get_packets():
    # to fetch from DB
    return [{"id": 1, "src_ip": "192.168.0.10", "dst_ip": "10.0.0.5", "protocol": "TCP"}]

#metrics endpoint
@app.get("/metrics")
def get_metrics():
    #to return real evaluation metrics
    return {"cic_accuracy": 0.9956, "nsl_accuracy": 0.9652}

#models endpoint
@app.get("/models")
def get_models():
    #to list trained models stored in DB
    return [
        {"name": "decision_tree_cic", "accuracy": 0.9956},
        {"name": "decision_tree_nsl", "accuracy": 0.9652}
    ]