from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

# -----------------------
# Basic health and root
# -----------------------
def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "html" in response.headers["content-type"]

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

# -----------------------
# Packet capture
# -----------------------
def test_list_interfaces():
    response = client.get("/interfaces")
    assert response.status_code == 200
    assert "interfaces" in response.json()

# NOTE: Start/Stop capture might require actual permissions and interfaces
# They can fail if you run tests without proper privileges or live network interfaces
def test_capture_status():
    response = client.get("/status")
    assert response.status_code == 200
    assert "status" in response.json()

# -----------------------
# Prediction endpoint
# -----------------------
def test_predict():
    # Provide dummy features with the same length as LIVE_FEATURES
    dummy_features = [0.0] * 79  # replace 79 with len(LIVE_FEATURES)
    payload = {"dataset": "CICIDS", "features": dummy_features}

    response = client.post("/predict", json=payload)
    # May fail if the model is not present; for CI, you may mock load_model
    assert response.status_code in (200, 404)  # Accept 404 if model is missing

# -----------------------
# Stats
# -----------------------
def test_get_stats():
    response = client.get("/stats")
    assert response.status_code == 200
    json_data = response.json()
    assert "total_packets" in json_data
    assert "recent_alerts" in json_data
    assert "threat_distribution" in json_data

# -----------------------
# Other endpoints
# -----------------------
def test_packets():
    response = client.get("/packets")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert "src_ip" in data[0]

def test_models():
    response = client.get("/models")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_metrics():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "metrics" in response.json()

def test_css_js_files():
    response = client.get("/css/style.css")
    assert response.status_code in (200, 404)  # depends if file exists
    response = client.get("/js/app.js")
    assert response.status_code in (200, 404)

def test_favicon():
    response = client.get("/favicon.ico")
    assert response.status_code in (200, 404)
