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

