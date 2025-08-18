import sqlite3
from pathlib import Path

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
    