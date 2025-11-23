# LAI-IDS (Lightweight AI Intrusion Detection System)

A minimal, resource-friendly IDS that captures network traffic, extracts features, and classifies activity with a lightweight ML model. It also gives reports for the capture sessions. It is built with **FastAPI** and **scikit-learn**.

## Quickstart

```bash
# Create & activate a virtual environment
python -m venv .venv
# Windows: 
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python scripts/setup_db.py

# Train Decision Tree model
python -m app.ml.train_DT_model

# Train Random Forest model  
python -m app.ml.train_RF_model

# Run API in virtual environment
uvicorn app.main:app --reload
