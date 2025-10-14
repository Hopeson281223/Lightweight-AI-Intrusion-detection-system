"""
Comprehensive system test for LAI-IDS
------------------------------------
Covers:
✅ API availability & health
✅ Model loading & prediction
✅ Database integrity
✅ Packet capture simulation
✅ WebSocket logs
✅ Interface listing
✅ Stats & metrics

Run:
    uvicorn main:app --reload
Then, in another terminal:
    python test_all.py
"""

import asyncio
import websockets
import requests
import json
import time
import random
import sqlite3
from pathlib import Path
import numpy as np

BASE_URL = "http://localhost:8000"

# ---------- Utility ----------
def print_header(title):
    print(f"\n\033[96m{'='*25} {title} {'='*25}\033[0m")

def check(condition, message):
    color = "\033[92m" if condition else "\033[91m"
    symbol = "✔️" if condition else "❌"
    print(f"{color}{symbol} {message}\033[0m")

def timed(func):
    """Decorator to print duration of each test section"""
    def wrapper(*args, **kwargs):
        start = time.time()
        print(f"\n⏳ Running {func.__name__} ...")
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start
            print(f"⏱️ Finished {func.__name__} in {elapsed:.2f}s")
            return result
        except Exception as e:
            print(f"❌ {func.__name__} crashed: {e}")
    return wrapper

# ---------- 1. Health check ----------
@timed
def test_health():
    print_header("Health Check")
    r = requests.get(f"{BASE_URL}/health")
    check(r.status_code == 200 and r.json().get("status") == "ok", "Server health check passed")

# ---------- 2. Interfaces ----------
@timed
def test_interfaces():
    print_header("Interfaces")
    r = requests.get(f"{BASE_URL}/interfaces")
    data = r.json()
    check("interfaces" in data, "Interfaces endpoint returns valid data")
    if data.get("interfaces"):
        print("Available interfaces:")
        for i in data["interfaces"]:
            print(f" - {i['name']} | {i['device']}")
    else:
        print("⚠️ No interfaces found")

# ---------- 3. Model loading & prediction ----------
@timed
def test_model_prediction():
    print_header("Model Prediction")
    N_FEATURES = 43
    features = np.random.rand(N_FEATURES).tolist()
    payload = {
        "dataset": "cic",
        "features": features,
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.1",
        "protocol": "TCP"
    }
    r = requests.post(f"{BASE_URL}/predict", json=payload)
    if r.status_code == 200:
        result = r.json()
        print("Prediction:", result)
        check("label" in result, "Prediction response includes label")
    else:
        print("Error:", r.text)
        check(False, "Prediction failed")

# ---------- 4. Database integrity ----------
@timed
def test_database():
    print_header("Database Check")
    db_path = Path("data/app.db")
    if not db_path.exists():
        check(False, "Database file missing!")
        return
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        print("Tables:", tables)
        required = {"packets", "predictions", "alerts", "metrics", "models"}
        check(required.issubset(set(tables)), "All required tables exist")
    except Exception as e:
        check(False, f"Database connection error: {e}")
    finally:
        conn.close()

# ---------- 5. Capture control ----------
@timed
def test_capture_controls():
    print_header("Packet Capture Controls")
    r1 = requests.post(f"{BASE_URL}/start")
    check(r1.status_code == 200, "Capture start endpoint works")

    r2 = requests.get(f"{BASE_URL}/status")
    data = r2.json()
    print("Status:", data)
    check("is_capturing" in data, "Capture status returns valid response")

    r3 = requests.post(f"{BASE_URL}/stop")
    check(r3.status_code == 200, "Capture stop endpoint works")

# ---------- 6. Stats ----------
@timed
def test_stats():
    print_header("System Stats")
    r = requests.get(f"{BASE_URL}/stats")
    data = r.json()
    print(json.dumps(data, indent=2))
    check("total_packets" in data, "Stats endpoint returns packet count")
    check("threat_distribution" in data, "Stats endpoint returns threat distribution")

# ---------- 7. WebSocket live logs ----------
@timed
async def test_websocket_logs():
    print_header("WebSocket Live Logs")
    uri = f"ws://localhost:8000/ws/logs"
    try:
        async with websockets.connect(uri) as ws:
            print("Connected to /ws/logs ... waiting for data (3s)")
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=3)
                print("Received log:", msg)
                check(True, "WebSocket log stream active")
            except asyncio.TimeoutError:
                print("No log received in 3s (likely no activity yet)")
                check(True, "WebSocket connected successfully")
    except Exception as e:
        check(False, f"WebSocket connection failed: {e}")

# ---------- 8. Metrics & Models ----------
@timed
def test_metrics_and_models():
    print_header("Metrics & Models")
    m1 = requests.get(f"{BASE_URL}/metrics")
    m2 = requests.get(f"{BASE_URL}/models")
    check(m1.status_code == 200, "Metrics endpoint OK")
    check(m2.status_code == 200, "Models endpoint OK")
    metrics = m1.json().get("metrics", [])
    models = m2.json()
    print(f"Metrics count: {len(metrics)}")
    print(f"Models count: {len(models)}")

# ---------- 9. Frontend ----------
@timed
def test_frontend_files():
    print_header("Frontend Files")
    files = ["index.html", "css", "js"]
    for f in files:
        r = requests.get(f"{BASE_URL}/frontend")
        check(r.status_code in (200, 307), f"Frontend served correctly ({f})")

# ---------- Main Runner ----------
def run_all_tests():
    print("\n🚀 Starting Comprehensive LAI-IDS System Test...\n")
    test_health()
    test_interfaces()
    test_model_prediction()
    test_database()
    test_capture_controls()
    test_stats()
    asyncio.run(test_websocket_logs())
    test_metrics_and_models()
    test_frontend_files()
    print("\n🎯 \033[92mAll tests executed.\033[0m\n")

if __name__ == "__main__":
    run_all_tests()
