import sqlite3
from pathlib import Path
import json
from datetime import datetime

DB_PATH = Path("lai_ids.sqlite3")

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER,
    features_json TEXT
);

CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER,
    label TEXT,
    score REAL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prediction_id INTEGER,
    severity TEXT,
    message TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    value TEXT,
    ts TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    dataset TEXT,
    path TEXT,
    size_kb REAL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    feature_names_json TEXT,
    label_classes_json TEXT
)
"""

def get_db():
    """Return an SQLite connection with Row factory"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with schema"""
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()

def save_metrics(name, value):
    conn = get_db()
    conn.execute("INSERT INTO metrics (name, value) VALUES (?, ?)", (name, str(value)))
    conn.commit()
    conn.close()

def save_model_info(name, dataset, path, size_kb, feature_names=None, label_classes=None):
    """Save model metadata in DB"""
    conn = get_db()
    feature_names_json = json.dumps(feature_names) if feature_names else None
    label_classes_json = json.dumps(label_classes) if label_classes else None
    conn.execute("""
        INSERT INTO models (name, dataset, path, size_kb, feature_names_json, label_classes_json)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (name, dataset, str(path), size_kb, feature_names_json, label_classes_json))
    conn.commit()
    conn.close()
                 