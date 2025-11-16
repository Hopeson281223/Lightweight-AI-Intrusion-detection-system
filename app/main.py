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
from datetime import datetime, timedelta
from collections import deque
import io
import re
import json
import psutil
import time
import os 
import joblib
import numpy as np
import asyncio
from app.storage.db import init_db, get_db, get_current_session_stats, get_recent_sessions
from app.ml.preprocess import LIVE_FEATURES, pd

class SystemMonitor:
    def __init__(self):
        self.app_start_time = time.time()
        self.process = psutil.Process()
        
    def get_app_cpu_usage(self):
        """Get CPU usage for this specific process"""
        try:
            return self.process.cpu_percent(interval=0.1)
        except:
            return 0
    
    def get_app_memory_usage(self):
        """Get memory usage for this specific process"""
        try:
            memory_info = self.process.memory_info()
            return memory_info.rss / (1024 * 1024)  # Convert to MB
        except:
            return 0
    
    def get_app_memory_percent(self):
        """Get memory usage as percentage of total system memory"""
        try:
            return self.process.memory_percent()
        except:
            return 0
    
    def get_app_uptime(self):
        """Get application uptime"""
        uptime_seconds = time.time() - self.app_start_time
        return self.format_uptime(uptime_seconds)
    
    def format_uptime(self, seconds):
        """Format uptime to human readable format"""
        days = seconds // (24 * 3600)
        seconds = seconds % (24 * 3600)
        hours = seconds // 3600
        seconds %= 3600
        minutes = seconds // 60
        seconds %= 60
        return f"{int(days)} days, {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"

# Initialize the monitor
system_monitor = SystemMonitor()

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

# Prediction request model
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

    # Supports both decision_tree and random_forest
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
def start_capture(interface: str = None, model_type: str = "random_forest"):  
    """Start live packet capture on specific interface"""
    if interface:
        success = packet_capture.start_capture(interface, model_type)  # PASS model_type
    else:
        success = packet_capture.start_capture(model_type=model_type)  # PASS model_type
    
    if success:
        return {
            "status": "capture_started", 
            "interface": packet_capture.current_interface,
            "model_used": model_type  
        }
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
    """Get system statistics - SESSION BASED with proper current session handling"""
    try:
        # Get current session info from packet capture
        capture_status = packet_capture.get_status()
        current_session_id = capture_status.get("session_id")
        is_capturing = capture_status.get("is_capturing", False)
        
        print(f"Stats request - Session: {current_session_id}, Capturing: {is_capturing}")
        
        # If we have a current session (even if not capturing), use its data
        if current_session_id:
            session_stats = get_current_session_stats(current_session_id)
            
            # If session exists in database, use its data
            if session_stats["session_info"]:
                return {
                    "threat_distribution": session_stats["threat_distribution"],
                    "recent_alerts": session_stats["recent_alerts"],
                    "capture_status": capture_status,
                    "session_id": current_session_id,
                    "session_based": True
                }
        
        # Fallback: Get the most recently ended session
        conn = get_db()
        cur = conn.cursor()
        
        # Get the most recent session (regardless of status)
        cur.execute("""
            SELECT id FROM sessions 
            ORDER BY start_time DESC 
            LIMIT 1
        """)
        recent_session = cur.fetchone()
        
        if recent_session:
            recent_session_id = recent_session[0]
            session_stats = get_current_session_stats(recent_session_id)
            
            # Update capture status to reflect we're showing recent session, not current
            capture_status["is_capturing"] = False
            capture_status["session_id"] = recent_session_id
            
            return {
                "threat_distribution": session_stats["threat_distribution"],
                "recent_alerts": session_stats["recent_alerts"],
                "capture_status": capture_status,
                "session_id": recent_session_id,
                "session_based": True
            }
        
        # Final fallback - no sessions at all
        conn.close()
        return {
            "threat_distribution": {},
            "recent_alerts": [],
            "capture_status": capture_status,
            "session_based": False
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
        "model_type": req.model_type 
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
                        "timestamp": formatted_time,  
                        "src_ip": log_data.get("src_ip", "N/A"),
                        "dst_ip": log_data.get("dst_ip", "N/A"), 
                        "protocol": log_data.get("protocol", "N/A"),
                        "label": log_data.get("label", "UNKNOWN"),
                        "confidence": log_data.get("confidence"),
                        "message": log_data.get("message", log_entry)
                    })
                    print(f"Added log to session: {formatted_time} - {log_data.get('label', 'UNKNOWN')}")
                    
                    # Also update the log entry to include date for WebSocket display
                    log_data["timestamp"] = formatted_time
                    await websocket.send_text(json.dumps(log_data))
                    
                except Exception as e:
                    print(f"Error adding log to session: {e}")
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

@app.get("/system")
def get_system_info():
    """Get LAI-IDS application specific system information"""
    try:
        # Application-specific metrics
        app_cpu = round(system_monitor.get_app_cpu_usage(), 1)
        app_memory_percent = round(system_monitor.get_app_memory_percent(), 1)
        app_memory_mb = round(system_monitor.get_app_memory_usage(), 1)
        app_uptime = system_monitor.get_app_uptime()
        
        # System-wide metrics for comparison (optional)
        system_cpu = round(psutil.cpu_percent(interval=0.1), 1)
        system_memory = psutil.virtual_memory()
        system_memory_percent = round(system_memory.percent, 1)
        
        return {
            # Application metrics
            'cpu': app_cpu,
            'memory': app_memory_percent,
            'memory_mb': app_memory_mb,
            'uptime': app_uptime,
            'version': '0.1.0',
            
            # System metrics for comparison (optional)
            'system_cpu': system_cpu,
            'system_memory': system_memory_percent,
            'total_memory_gb': round(system_memory.total / (1024**3), 1)
        }
    except Exception as e:
        print(f"Error getting system info: {e}")
        # Fallback data
        return {
            'cpu': 0,
            'memory': 0,
            'memory_mb': 0,
            'uptime': 'N/A',
            'version': '0.1.0',
            'system_cpu': 0,
            'system_memory': 0,
            'total_memory_gb': 0
        }
      
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
    live_logs = report_data.get("live_logs", [])

    buffer = io.BytesIO()
    
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import inch
    
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=A4,
        topMargin=0.5*inch,
        bottomMargin=0.5*inch,
        leftMargin=0.4*inch,
        rightMargin=0.4*inch
    )
    
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph(f"LAI-IDS Session Report: {session_id}", styles["Title"]))
    elements.append(Spacer(1, 12))

    # Session info with better interface name formatting
    elements.append(Paragraph("<b>Session Information</b>", styles["Heading2"]))
    
    # Format interface name properly
    interface_name = session.get("interface", "Unknown Interface")

    # Get model information from session
    model_used = session.get("model_used", "random_forest")
    model_display_name = "Random Forest" if model_used == "random_forest" else "Decision Tree"
        
    # Clean up interface name for display
    def format_interface_name(interface):
        """Convert raw interface name to user-friendly format"""
        if not interface or interface == "Unknown Interface":
            return "Not Specified"
        
        # Map of device GUIDs to their actual names from your system
        interface_mapping = {
            'B45B858F-332B-4B73-BD88-78A970DA5CA8': 'Ethernet 2',
            '99D899F9-FC26-11EE-B272-806E6F6E6963': 'Loopback',
            '38B644DD-945C-4322-A099-2CBDB55C682B': 'Wi-Fi',
            '07374750-E68B-490E-9330-9FD785CD71B6': '6to4 Adapter',
            '9830E727-F5F6-4CF9-B731-2448C890CD2B': 'Bluetooth',
            '8D342B22-886E-4332-A4D1-06EE75FCF9D1': 'USB Ethernet',
            'B9A4468E-586B-4B7D-9CF6-2A500407E66F': 'Kernel Debugger',
            '9B9A36D7-2119-11F0-B321-50EB71026F15': 'Ethernet 2 (Npcap)',
            'BA72FB83-BBEC-49CA-93CB-E05DDED0E27D': 'RAS Adapter',
            '2EE2C70C-A092-4D88-A654-98C8D7645CD5': 'IP-HTTPS',
            '93123211-9629-4E04-82F0-EA2E4F221468': 'Teredo',
            '3EE5C085-E9EF-11EF-B30B-50EB71026F15': 'Wi-Fi (Npcap)'
        }
        
        # Extract GUID from Windows device path
        if interface.startswith(r'\Device\NPF_'):
            guid_match = re.search(r'\{([A-F0-9-]+)\}', interface)
            if guid_match:
                guid = guid_match.group(1)
                return interface_mapping.get(guid, 'Network Adapter')
        
        return interface
    formatted_interface = format_interface_name(interface_name)
    
    # Format dates properly
    def format_date(date_string):
        """Format date string for better readability"""
        if not date_string or date_string == 'N/A':
            return 'N/A'
        try:
            # Handle both ISO format and existing formatted dates
            if 'T' in date_string:  # ISO format
                dt = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            else:
                return date_string  # Already formatted
        except:
            return date_string
    
    info_data = [
        ["Session ID", session_id],
        ["Network Interface", formatted_interface],
        ["ML Model Used", model_display_name],
        ["Start Time", format_date(session.get("start_time"))],
        ["End Time", format_date(session.get("end_time"))],
        ["Total Packets", str(session.get("total_packets", 0))],
        ["Total Predictions", str(session.get("total_predictions", 0))],
        ["Total Alerts", str(session.get("total_alerts", 0))],
        ["Capture Status", "Completed" if session.get("end_time") else "In Progress"],
    ]
    
    info_table = Table(info_data, colWidths=[150, 350])
    info_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 2), (-1, 2), colors.whitesmoke),  # ML Model row
        ("BACKGROUND", (0, 4), (-1, 4), colors.whitesmoke),  # Start Time row
        ("BACKGROUND", (0, 6), (-1, 6), colors.whitesmoke),  # Total Packets row
        ("BACKGROUND", (0, 8), (-1, 8), colors.whitesmoke),  # Capture Status row
        ("BOX", (0, 0), (-1, -1), 1, colors.black),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),  # Header row bold
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 12))

    # Prediction Summary - IMPROVED: Better formatting and colors
    elements.append(Paragraph("<b>Prediction Summary</b>", styles["Heading2"]))
    
    # Ensure we have both NORMAL and ANOMALOUS keys
    normal_count = predictions.get("NORMAL", 0)
    anomalous_count = predictions.get("ANOMALOUS", 0)
    total_predictions = normal_count + anomalous_count
    
    # Calculate percentages
    normal_percent = (normal_count / total_predictions * 100) if total_predictions > 0 else 0
    anomalous_percent = (anomalous_count / total_predictions * 100) if total_predictions > 0 else 0
    
    pred_data = [
        ["Label", "Count", "Percentage"],
        ["NORMAL", str(normal_count), f"{normal_percent:.1f}%"],
        ["ANOMALOUS", str(anomalous_count), f"{anomalous_percent:.1f}%"],
        ["TOTAL", str(total_predictions), "100%"]
    ]
    
    pred_table = Table(pred_data, colWidths=[200, 100, 100])
    
    # Create table style with conditional coloring
    pred_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#d4edda")),  # Green for normal
        ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#f8d7da")),  # Red for anomalous
        ("BACKGROUND", (0, 3), (-1, 3), colors.lightgrey),  # Grey for total
        ("BOX", (0, 0), (-1, -1), 1, colors.black),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 3), (-1, 3), "Helvetica-Bold"),  # Total row bold
    ])
    
    pred_table.setStyle(pred_style)
    elements.append(pred_table)
    elements.append(Spacer(1, 12))

    # Rest of your existing code for Alerts and Live Logs remains the same...
    # Alerts section
    elements.append(Paragraph("<b>Recent Alerts</b>", styles["Heading2"]))
    if alerts:
        alert_data = [["Severity", "Message", "Timestamp"]] + [
            [a["severity"], a["message"], format_date(a["created_at"])] for a in alerts
        ]
        alert_table = Table(alert_data, colWidths=[80, 320, 100])
        alert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("BOX", (0, 0), (-1, -1), 1, colors.black),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("WORDWRAP", (1, 0), (1, -1), True),
        ]))
        elements.append(alert_table)
    else:
        elements.append(Paragraph("No alerts recorded for this session.", styles["Normal"]))
    
    elements.append(Spacer(1, 12))

    # Live Logs Section
    elements.append(Paragraph("<b>Live Session Logs</b>", styles["Heading2"]))
    
    if live_logs:
        log_data = [["Timestamp", "Source IP", "Dest IP", "Protocol", "Prediction", "Confidence"]]
        
        for log_entry in live_logs:
            timestamp = log_entry.get("timestamp", "N/A")
            src_ip = log_entry.get("src_ip", "N/A")
            dst_ip = log_entry.get("dst_ip", "N/A")
            protocol = log_entry.get("protocol", "N/A")
            label = log_entry.get("label", "UNKNOWN")
            confidence = log_entry.get("confidence")
            
            # Truncate long IP addresses to prevent overflow
            if len(src_ip) > 15:
                src_ip = src_ip[:12] + "..."
            if len(dst_ip) > 15:
                dst_ip = dst_ip[:12] + "..."
            
            conf_text = f"{confidence:.2f}" if confidence is not None else "N/A"
            
            log_data.append([timestamp, src_ip, dst_ip, protocol, label, conf_text])
        
        log_table = Table(log_data, colWidths=[70, 75, 75, 50, 60, 50])
        
        log_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("BOX", (0, 0), (-1, -1), 1, colors.black),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("ALIGN", (1, 1), (2, -1), "LEFT"),
            ("WORDWRAP", (0, 0), (-1, -1), True),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ]))
        
        elements.append(log_table)
        
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(f"<i>Total log entries: {len(live_logs)}</i>", styles["Normal"]))
        
        threat_count = sum(1 for log in live_logs if log.get("label") == "ANOMALOUS")
        elements.append(Paragraph(f"<i>Threats detected: {threat_count}</i>", styles["Normal"]))
        
    else:
        elements.append(Paragraph("No live logs recorded for this session.", styles["Normal"]))
    
    elements.append(Spacer(1, 12))

    # Final Summary Section
    elements.append(Paragraph("<b>Security Summary</b>", styles["Heading2"]))
    
    summary_data = [
        ["Metric", "Value", "Risk Level"],
        ["Total Predictions", str(total_predictions), "Baseline"],
        ["Normal Traffic", f"{normal_count} ({normal_percent:.1f}%)", "Low"],
        ["Anomalous Traffic", f"{anomalous_count} ({anomalous_percent:.1f}%)", 
         "High" if anomalous_percent > 5 else "Medium" if anomalous_percent > 1 else "Low"],
        ["Alerts Generated", str(session.get("total_alerts", 0)), 
         "High" if session.get("total_alerts", 0) > 10 else "Medium" if session.get("total_alerts", 0) > 5 else "Low"],
        ["Threat Detection Rate", f"{(anomalous_count/total_predictions*100) if total_predictions > 0 else 0:.2f}%", 
         "Monitor" if anomalous_count > 0 else "Secure"],
    ]
    
    summary_table = Table(summary_data, colWidths=[150, 120, 80])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOX", (0, 0), (-1, -1), 1, colors.black),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))
    elements.append(summary_table)

    try:
        doc.build(elements)
        buffer.seek(0)

        filename = f"LAI-IDS_Report_{session_id}.pdf"
        
        from fastapi import Response
        return Response(
            content=buffer.getvalue(),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        print(f"PDF generation error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")
    
@app.get("/debug/sessions")
def debug_sessions():
    """Debug endpoint to see all sessions"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, start_time, end_time, total_predictions FROM sessions ORDER BY start_time DESC LIMIT 5")
    sessions = [dict(row) for row in cur.fetchall()]
    conn.close()
    
    current_session = packet_capture.get_status()
    
    return {
        "current_session": current_session,
        "recent_sessions": sessions
    }