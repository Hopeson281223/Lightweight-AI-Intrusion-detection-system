from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from pydantic import BaseModel
from pathlib import Path
from app.packet_capture.packet_capture import packet_capture
from datetime import datetime
from collections import deque
import io
import json
import joblib
import numpy as np
import asyncio
from app.storage.db import init_db, get_db, get_current_session_stats, get_recent_sessions
from app.ml.preprocess import LIVE_FEATURES, pd

# Directories
MODEL_DIR = Path("models")
PREPROCESSED_DIR = Path("data/preprocessed")

# Cache and live logs
loaded_models = {}
loaded_meta = {}
live_logs = deque()  # Uses deque for efficient pops

# FastAPI app
app = FastAPI(title="LAI-IDS", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serves frontend
app.mount("/frontend", StaticFiles(directory="app/frontend"), name="frontend")

@app.get("/")
def root():
    return FileResponse("app/frontend/index.html")

# Startup
@app.on_event("startup")
def startup_event():
    init_db()

# Request models
class PredictRequest(BaseModel):
    dataset: str
    features: list[float]
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None
    model_type: str = "decision_tree"

# Load model
def load_model(dataset: str, model_type: str = "decision_tree"):
    """Load model and metadata from disk or cache"""
    cache_key = f"{dataset}_{model_type}"
    
    if cache_key in loaded_models:
        return loaded_models[cache_key], loaded_meta[cache_key]

    # Support both decision_tree and random_forest
    if model_type == "random_forest":
        model_path = MODEL_DIR / f"random_forest_{dataset}_model.joblib"
    else:
        model_path = MODEL_DIR / f"decision_tree_{dataset}_model.joblib"

    meta_path = PREPROCESSED_DIR / dataset / f"{dataset}_ALL_meta.pkl"
    ct_path = PREPROCESSED_DIR / dataset / f"{dataset}_ALL_ct.joblib"
    le_path = PREPROCESSED_DIR / dataset / f"{dataset}_ALL_label_encoder.joblib"

    if not model_path.exists():
        raise HTTPException(status_code=404, detail=f"Model for {dataset} not found")

    model = joblib.load(model_path)
    loaded_models[cache_key] = model

    meta = joblib.load(meta_path) if meta_path.exists() else {}
    ct = joblib.load(ct_path) if ct_path.exists() else None
    le = joblib.load(le_path) if le_path.exists() else None

    loaded_meta[cache_key] = {**meta, "ct": ct, "label_encoder": le, "model_type": model_type}
    return model, loaded_meta[cache_key]

# Health check
@app.get("/health")
def health_check():
    return {"status": "ok"}

# Capture
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
    """List available network interfaces with detailed status"""
    interfaces = packet_capture.list_available_interfaces()
    
    # Add additional status information
    enhanced_interfaces = []
    for iface in interfaces:
        enhanced_iface = {**iface}
        
        # Add status text
        if iface.get("active"):
            enhanced_iface["status"] = "active"
            enhanced_iface["status_description"] = "Ready for capture"
        else:
            enhanced_iface["status"] = "inactive" 
            enhanced_iface["status_description"] = "Interface not active"
            
        enhanced_interfaces.append(enhanced_iface)
    
    return {"interfaces": enhanced_interfaces}

@app.post("/interface/{interface_name}")
def set_interface(interface_name: str):
    """Set the capture interface"""
    success = packet_capture.set_interface(interface_name)
    if success:
        return {"status": "interface_set", "interface": interface_name}
    else:
        raise HTTPException(status_code=500, detail=packet_capture.last_error or "Failed to set interface")

# stats
@app.get("/stats")
def get_stats():
    """Get system statistics - SESSION BASED"""
    try:
        # Get current session info from packet capture
        capture_status = packet_capture.get_status()
        current_session_id = capture_status.get("session_id")
        
        # Use session-based stats if available
        if current_session_id and capture_status.get("is_capturing"):
            from app.storage.db import get_current_session_stats
            session_stats = get_current_session_stats(current_session_id)
            
            return {
                "threat_distribution": session_stats["threat_distribution"],
                "recent_alerts": session_stats["recent_alerts"],
                "capture_status": capture_status,
                "session_id": current_session_id,
                "session_based": True  # Flag to indicate session-based data
            }
        else:
            # Fallback to recent session or all-time data
            conn = get_db()
            cur = conn.cursor()
            
            # Get most recent session's threat distribution
            cur.execute("""
                SELECT label, COUNT(*) as count 
                FROM predictions 
                WHERE session_id = (
                    SELECT id FROM sessions 
                    ORDER BY start_time DESC 
                    LIMIT 1
                )
                GROUP BY label
            """)
            threat_rows = cur.fetchall()
            threat_distribution = {row[0]: row[1] for row in threat_rows} if threat_rows else {}
            
            # Get recent alerts
            cur.execute("""
                SELECT a.severity, a.message, a.created_at, p.label 
                FROM alerts a
                JOIN predictions p ON a.prediction_id = p.id
                ORDER BY a.created_at DESC 
                LIMIT 10
            """)
            alert_rows = cur.fetchall()
            recent_alerts = [
                {
                    "severity": row[0],
                    "message": row[1], 
                    "timestamp": row[2],
                    "label": row[3]
                }
                for row in alert_rows
            ]
            
            conn.close()
            
            return {
                "threat_distribution": threat_distribution,
                "recent_alerts": recent_alerts,
                "capture_status": capture_status,
                "session_based": False  # Flag to indicate fallback data
            }
        
    except Exception as e:
        print(f"Error getting stats: {e}")
        return {
            "threat_distribution": {},
            "recent_alerts": [],
            "capture_status": packet_capture.get_status(),
            "error": str(e)
        }
        
# Prediction
# Prediction
@app.post("/predict")
def predict(req: PredictRequest):
    model, meta = load_model(req.dataset, req.model_type)  # Pass model_type here

    ct = meta.get("ct")
    if ct is None:
        raise HTTPException(status_code=500, detail="ColumnTransformer not found in model meta.")

    if len(req.features) != len(LIVE_FEATURES):
        raise HTTPException(
            status_code=400,
            detail=f"Expected {len(LIVE_FEATURES)} features (order must match LIVE_FEATURES)."
        )

    df = pd.DataFrame([req.features], columns=LIVE_FEATURES)

    # log-transform extreme columns
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

    # Add structured log to live feed
    log_entry = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "label": label,
        "confidence": float(prob) if prob is not None else None,
        "src_ip": req.src_ip or "N/A",
        "dst_ip": req.dst_ip or "N/A",
        "protocol": req.protocol or "N/A",
        "message": f"Prediction result: {label} (conf: {prob:.2f})" if prob else f"Prediction result: {label}",
        "model_type": req.model_type  # Add model type to logs
    }
    live_logs.append(json.dumps(log_entry))

    return {
        "dataset": req.dataset,
        "prediction": int(pred),
        "label": label,
        "confidence": float(prob) if prob is not None else None,
        "model_type": req.model_type  # Return model type in response
    }

# WebSocket for live logs
@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            if live_logs:
                log_entry = live_logs.popleft()
                
                # Store log in current session (in packet_capture memory)
                try:
                    # Parse the log entry to get structured data
                    log_data = json.loads(log_entry)
                    
                    # Create log entry with FULL datetime
                    current_time = datetime.now()
                    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    packet_capture.session_logs.append({
                        "timestamp": formatted_time,  # Full date and time
                        "src_ip": log_data.get("src_ip", "N/A"),
                        "dst_ip": log_data.get("dst_ip", "N/A"), 
                        "protocol": log_data.get("protocol", "N/A"),
                        "label": log_data.get("label", "UNKNOWN"),
                        "confidence": log_data.get("confidence"),
                        "message": log_data.get("message", log_entry)
                    })
                    print(f"📝 Added log to session: {formatted_time} - {log_data.get('label', 'UNKNOWN')}")
                    
                    # Also update the log entry to include date for WebSocket display
                    log_data["timestamp"] = formatted_time
                    await websocket.send_text(json.dumps(log_data))
                    
                except Exception as e:
                    print(f"⚠️ Error adding log to session: {e}")
                    # Still add raw log if JSON parsing fails
                    current_time = datetime.now()
                    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    packet_capture.session_logs.append({
                        "timestamp": formatted_time,
                        "message": log_entry
                    })
                    await websocket.send_text(log_entry)
            await asyncio.sleep(0.5)
    except Exception as e:
        print(f"[WS] Connection closed: {e}")

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

@app.get("/available-models")
def get_available_models():
    """Get list of available models for the frontend"""
    available_models = []
    
    # Check for decision tree model
    dt_path = MODEL_DIR / "decision_tree_cic_model.joblib"
    if dt_path.exists():
        available_models.append({
            "name": "Decision Tree",
            "type": "decision_tree",
            "description": "Fast and lightweight model for real-time detection",
            "accuracy": "~99%",
            "speed": "⚡ Fast",
            "size": "Small"
        })
    
    # Check for random forest model
    rf_path = MODEL_DIR / "random_forest_cic_model.joblib"
    if rf_path.exists():
        available_models.append({
            "name": "Random Forest", 
            "type": "random_forest",
            "description": "High-accuracy ensemble model for reliable detection",
            "accuracy": "99.86%",
            "speed": "🐢 Slower", 
            "size": "Large"
        })
    
    return {"available_models": available_models}

@app.get("/models")
def get_models():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT name, dataset, path, size_kb, timestamp, model_type FROM models ORDER BY timestamp DESC")
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "name": r[0], 
            "dataset": r[1], 
            "path": r[2], 
            "size_kb": r[3], 
            "timestamp": r[4],
            "model_type": r[5] or "decision_tree"  # Handle NULL values
        }
        for r in rows
    ]

# Session management endpoints
@app.get("/sessions")
def get_sessions(limit: int = 10):
    """Get recent capture sessions"""
    try:
        from app.storage.db import get_recent_sessions
        sessions = get_recent_sessions(limit)
        return {"sessions": sessions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting sessions: {e}")

@app.get("/sessions/{session_id}")
def get_session_details(session_id: str):
    """Get detailed information for a specific session"""
    try:
        from app.storage.db import get_current_session_stats
        session_stats = get_current_session_stats(session_id)
        
        if not session_stats["session_info"]:
            raise HTTPException(status_code=404, detail="Session not found")
            
        return {
            "session_info": session_stats["session_info"],
            "threat_distribution": session_stats["threat_distribution"],
            "recent_alerts": session_stats["recent_alerts"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting session details: {e}")
    
@app.get("/reports")
def list_reports():
    """List all generated session reports"""
    conn = get_db()
    cur = conn.execute("""
        SELECT r.id, r.session_id, r.title, r.created_at, s.start_time, s.end_time, s.interface
        FROM reports r
        LEFT JOIN sessions s ON r.session_id = s.id
        ORDER BY r.created_at DESC
    """)
    reports = [dict(row) for row in cur.fetchall()]
    conn.close()
    return {"reports": reports}

@app.get("/reports/{session_id}")
def get_report_details(session_id: str):
    """View JSON report data (summary)"""
    conn = get_db()
    cur = conn.execute("SELECT report_data FROM reports WHERE session_id = ?", (session_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return json.loads(row["report_data"])


@app.get("/reports/{session_id}/download")
def download_report(session_id: str):
    """Generate and return a PDF report for a specific session"""
    conn = get_db()
    cur = conn.execute("SELECT report_data FROM reports WHERE session_id = ?", (session_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    
    report_data = json.loads(row["report_data"])
    session = report_data["session"]
    predictions = report_data["predictions"]
    alerts = report_data["alerts"]
    live_logs = report_data.get("live_logs", [])  # Get live logs from report data

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph(f"LAI-IDS Session Report: {session_id}", styles["Title"]))
    elements.append(Spacer(1, 12))

    # Session info
    elements.append(Paragraph("<b>Session Information</b>", styles["Heading2"]))
    info_data = [
        ["Interface", session["interface"]],
        ["Start Time", session["start_time"]],
        ["End Time", session["end_time"]],
        ["Total Packets", session["total_packets"]],
        ["Total Predictions", session["total_predictions"]],
        ["Total Alerts", session["total_alerts"]],
    ]
    info_table = Table(info_data, colWidths=[150, 350])
    info_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("BOX", (0, 0), (-1, -1), 1, colors.black),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 12))

    # Prediction Summary
    elements.append(Paragraph("<b>Prediction Summary</b>", styles["Heading2"]))
    pred_data = [["Label", "Count"]] + [[k, v] for k, v in predictions.items()]
    pred_table = Table(pred_data, colWidths=[250, 250])
    pred_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("BOX", (0, 0), (-1, -1), 1, colors.black),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(pred_table)
    elements.append(Spacer(1, 12))

    # Alerts
    elements.append(Paragraph("<b>Recent Alerts</b>", styles["Heading2"]))
    if alerts:
        alert_data = [["Severity", "Message", "Timestamp"]] + [
            [a["severity"], a["message"], a["created_at"]] for a in alerts
        ]
        alert_table = Table(alert_data, colWidths=[100, 300, 100])
        alert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("BOX", (0, 0), (-1, -1), 1, colors.black),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(alert_table)
    else:
        elements.append(Paragraph("No alerts recorded for this session.", styles["Normal"]))
    
    elements.append(Spacer(1, 12))

    # === ADD LIVE LOGS SECTION ===
    elements.append(Paragraph("<b>Live Session Logs</b>", styles["Heading2"]))
    
    if live_logs:
        # Show all logs in a readable format
        log_data = [["Timestamp", "Source", "Destination", "Protocol", "Prediction", "Confidence"]]
        
        for log_entry in live_logs:
            timestamp = log_entry.get("timestamp", "N/A")
            src_ip = log_entry.get("src_ip", "N/A")
            dst_ip = log_entry.get("dst_ip", "N/A")
            protocol = log_entry.get("protocol", "N/A")
            label = log_entry.get("label", "UNKNOWN")
            confidence = log_entry.get("confidence")
            
            conf_text = f"{confidence:.2f}" if confidence else "N/A"
            
            log_data.append([timestamp, src_ip, dst_ip, protocol, label, conf_text])
        
        # Create live logs table
        log_table = Table(log_data, colWidths=[60, 80, 80, 50, 60, 50])
        log_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("BOX", (0, 0), (-1, -1), 1, colors.black),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.whitesmoke]),
        ]))
        elements.append(log_table)
        
        elements.append(Paragraph(f"<i>Total log entries: {len(live_logs)}</i>", styles["Normal"]))
    else:
        elements.append(Paragraph("No live logs recorded for this session.", styles["Normal"]))
    # ==============================

    doc.build(elements)
    buffer.seek(0)

    filename = f"LAI-IDS_Report_{session_id}.pdf"
    
    from fastapi import Response
    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )