from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
from app.packet_capture.packet_capture import packet_capture
import joblib
import numpy as np
from collections import deque
import asyncio

from app.storage.db import init_db, get_db
from app.ml.preprocess import LIVE_FEATURES, pd

# -----------------------
# Directories
# -----------------------
MODEL_DIR = Path("models")
PREPROCESSED_DIR = Path("data/preprocessed")

# -----------------------
# Cache and live logs
# -----------------------
loaded_models = {}
loaded_meta = {}
live_logs = deque()  # Use deque for efficient pops

# -----------------------
# FastAPI app
# -----------------------
app = FastAPI(title="LAI-IDS", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend
app.mount("/frontend", StaticFiles(directory="app/frontend"), name="frontend")

@app.get("/")
def root():
    return FileResponse("app/frontend/index.html")

# -----------------------
# Startup
# -----------------------
@app.on_event("startup")
def startup_event():
    init_db()

# -----------------------
# Request models
# -----------------------
class PredictRequest(BaseModel):
    dataset: str
    features: list[float]

# -----------------------
# Load model
# -----------------------
def load_model(dataset: str):
    """Load model and metadata from disk or cache"""
    if dataset in loaded_models:
        return loaded_models[dataset], loaded_meta[dataset]

    model_path = MODEL_DIR / f"decision_tree_{dataset}_model.joblib"
    meta_path = PREPROCESSED_DIR / dataset / f"{dataset}_ALL_meta.pkl"
    ct_path = PREPROCESSED_DIR / dataset / f"{dataset}_ALL_ct.joblib"
    le_path = PREPROCESSED_DIR / dataset / f"{dataset}_ALL_label_encoder.joblib"

    if not model_path.exists():
        raise HTTPException(status_code=404, detail=f"Model for {dataset} not found")

    model = joblib.load(model_path)
    loaded_models[dataset] = model

    meta = joblib.load(meta_path) if meta_path.exists() else {}
    ct = joblib.load(ct_path) if ct_path.exists() else None
    le = joblib.load(le_path) if le_path.exists() else None

    loaded_meta[dataset] = {**meta, "ct": ct, "label_encoder": le}
    return model, loaded_meta[dataset]

# -----------------------
# Health check
# -----------------------
@app.get("/health")
def health_check():
    return {"status": "ok"}

# -----------------------
# Capture
# -----------------------
@app.post("/start")
def start_capture(interface: str = None):
    """Start live packet capture on specific interface"""
    if interface:
        success = packet_capture.start_capture(interface)
    else:
        success = packet_capture.start_capture()
    
    if success:
        return {"status": "capture_started", "interface": packet_capture.current_interface}
    else:
        raise HTTPException(status_code=500, detail=packet_capture.last_error or "Failed to start capture")

@app.post("/stop")
def stop_capture():
    """Stop live packet capture"""
    success = packet_capture.stop_capture()
    if success:
        return {
            "status": "capture_stopped", 
            "packets_captured": packet_capture.packet_count,
            "message": f"Stopped capture with {packet_capture.packet_count} packets"
        }
    else:
        raise HTTPException(status_code=500, detail=packet_capture.last_error or "Failed to stop capture")

@app.get("/status")
def capture_status():
    """Get capture status"""
    return packet_capture.get_status()

@app.get("/interfaces")
def list_interfaces():
    """List available network interfaces"""
    interfaces = packet_capture.list_available_interfaces()
    return {"interfaces": interfaces}

@app.post("/interface/{interface_name}")
def set_interface(interface_name: str):
    """Set the capture interface"""
    success = packet_capture.set_interface(interface_name)
    if success:
        return {"status": "interface_set", "interface": interface_name}
    else:
        raise HTTPException(status_code=500, detail=packet_capture.last_error or "Failed to set interface")

# -----------------------
# stats
# -----------------------
@app.get("/stats")
def get_stats():
    """Get system statistics"""
    conn = get_db()
    try:
        cur = conn.cursor()
        
        # Total packets
        cur.execute("SELECT COUNT(*) FROM packets")
        total_packets = cur.fetchone()[0] or 0
        
        # Recent alerts (last hour)
        cur.execute("SELECT COUNT(*) FROM alerts WHERE created_at > datetime('now', '-1 hour')")
        recent_alerts_result = cur.fetchone()
        recent_alerts = recent_alerts_result[0] if recent_alerts_result else 0
        
        # Threat distribution
        cur.execute("SELECT label, COUNT(*) FROM predictions GROUP BY label")
        threat_rows = cur.fetchall()
        threat_distribution = {row[0]: row[1] for row in threat_rows} if threat_rows else {}
        
        # Capture status
        from app.packet_capture import packet_capture
        capture_status = packet_capture.get_status()
        
        return {
            "total_packets": total_packets,
            "recent_alerts": recent_alerts,
            "threat_distribution": threat_distribution,
            "capture_status": capture_status
        }
        
    except Exception as e:
        print(f"Error getting stats: {e}")
        return {
            "total_packets": 0,
            "recent_alerts": 0, 
            "threat_distribution": {},
            "error": str(e)
        }
    finally:
        conn.close()
# -----------------------
# Prediction
# -----------------------
@app.post("/predict")
def predict(req: PredictRequest):
    model, meta = load_model(req.dataset)

    ct = meta.get("ct")
    if ct is None:
        raise HTTPException(status_code=500, detail="ColumnTransformer not found in model meta.")

    if len(req.features) != len(LIVE_FEATURES):
        raise HTTPException(
            status_code=400,
            detail=f"Expected {len(LIVE_FEATURES)} features (order must match LIVE_FEATURES)."
        )

    df = pd.DataFrame([req.features], columns=LIVE_FEATURES)

    # Optional: log-transform extreme columns
    extreme_cols = ["Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s"]
    for col in extreme_cols:
        if col in df.columns:
            df[col] = np.log1p(df[col])

    # Preprocessing
    try:
        X_input_transformed = ct.transform(df)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Preprocessing failed: {str(e)}")

    # Prediction
    try:
        pred = model.predict(X_input_transformed)[0]
        prob = model.predict_proba(X_input_transformed).max() if hasattr(model, "predict_proba") else None
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Prediction failed: {str(e)}")

    # Map to label
    le = meta.get("label_encoder")
    if le is not None:
        label = le.inverse_transform([pred])[0]
    else:
        classes = meta.get("label_classes", [])
        label = classes[pred] if 0 <= pred < len(classes) else "UNKNOWN"

    # Confidence threshold
    CONF_THRESHOLD = 0.75
    if prob is not None and prob < CONF_THRESHOLD:
        label = "ANOMALOUS"

    # Add to live logs
    conf_display = f"{prob:.2f}" if prob is not None else "N/A"
    log_msg = f"{req.features[:5]} -> {label} (conf: {conf_display})"
    live_logs.append(log_msg)

    return {
        "dataset": req.dataset,
        "prediction": int(pred),
        "label": label,
        "confidence": float(prob) if prob is not None else None
    }

# -----------------------
# WebSocket for live logs
# -----------------------
@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            if live_logs:
                log_entry = live_logs.popleft()
                await websocket.send_text(log_entry)
            await asyncio.sleep(0.5)
    except Exception as e:
        print(f"[WS] Connection closed: {e}")

# -----------------------
# Other endpoints
# -----------------------
@app.get("/packets")
def get_packets():
    return [{"id": 1, "src_ip": "192.168.0.10", "dst_ip": "10.0.0.5", "protocol": "TCP"}]

@app.get("/metrics")
def get_metrics():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name, value, ts FROM metrics ORDER BY ts DESC")
    rows = cur.fetchall()
    conn.close()
    return {"metrics": [{"name": r[0], "value": r[1], "timestamp": r[2]} for r in rows]}

@app.get("/models")
def get_models():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name, dataset, path, size_kb, timestamp FROM models ORDER BY timestamp DESC")
    rows = cur.fetchall()
    conn.close()
    return [
        {"name": r[0], "dataset": r[1], "path": r[2], "size_kb": r[3], "timestamp": r[4]}
        for r in rows
    ]

# Serve CSS files from root
@app.get("/css/{filename}")
def get_css(filename: str):
    return FileResponse(f"app/frontend/css/{filename}")

# Serve JS files from root  
@app.get("/js/{filename}")
def get_js(filename: str):
    return FileResponse(f"app/frontend/js/{filename}")

# Serve frontend assets
@app.get("/favicon.ico")
def get_favicon():
    return FileResponse("app/frontend/favicon.ico")