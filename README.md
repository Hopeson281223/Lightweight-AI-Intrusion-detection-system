# LAI-IDS (Lightweight AI Intrusion Detection System)

A minimal, resource-friendly IDS that captures network traffic, extracts features, and classifies activity with a lightweight ML model. Built with **FastAPI** and **scikit-learn**.

## Quickstart

```bash
# Create & activate a virtual environment
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python scripts/setup_db.py

# Run API
uvicorn app.main:app --reload
# Open: http://127.0.0.1:8000/docs
