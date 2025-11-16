import sqlite3
from pathlib import Path
import json
from datetime import datetime
import time

DB_PATH = Path("lai_ids.sqlite3")

SCHEMA = """
-- Sessions table to track capture sessions
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    start_time TEXT,
    end_time TEXT,
    interface TEXT,
    total_packets INTEGER DEFAULT 0,
    total_predictions INTEGER DEFAULT 0,
    total_alerts INTEGER DEFAULT 0
);

-- Packets table with session tracking
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER,
    features_json TEXT,
    session_id TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions (id)
);

-- Predictions table with session tracking
CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    packet_id INTEGER,
    label TEXT,
    score REAL,
    session_id TEXT,
    created_at TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions (id),
    FOREIGN KEY (packet_id) REFERENCES packets (id)
);

-- Alerts table with proper timestamps
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prediction_id INTEGER,
    severity TEXT,
    message TEXT,
    session_id TEXT,
    created_at TEXT,
    FOREIGN KEY (prediction_id) REFERENCES predictions (id),
    FOREIGN KEY (session_id) REFERENCES sessions (id)
);

-- Existing tables
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    value TEXT,
    ts TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Reports table to store saved session reports
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    title TEXT,
    created_at TEXT,
    report_data TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions (id)
);

-- Models table with model_type support
CREATE TABLE IF NOT EXISTS models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    dataset TEXT,
    path TEXT,
    size_kb REAL,
    model_type TEXT DEFAULT 'decision_tree',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    feature_names_json TEXT,
    label_classes_json TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Live logs table to store WebSocket messages
CREATE TABLE IF NOT EXISTS live_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    log_data TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions (id)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id);
CREATE INDEX IF NOT EXISTS idx_live_logs_session ON live_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_predictions_session ON predictions(session_id);
CREATE INDEX IF NOT EXISTS idx_reports_session ON reports(session_id);
CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_time ON sessions(start_time);
CREATE INDEX IF NOT EXISTS idx_models_type ON models(model_type);
"""

def get_db():
    """Return an SQLite connection with Row factory"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with schema and handle migrations"""
    # Create database file if it doesn't exist
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    conn = get_db()
    try:
        # Check if we need to migrate
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row['name'] for row in cur.fetchall()]
        
        if not existing_tables:
            # Fresh install - create all tables
            print("Creating new database...")
            conn.executescript(SCHEMA)
            conn.commit()
            print("Database created successfully")
        else:
            # Existing database - run migrations
            migrate_db(conn, existing_tables)
            
    except Exception as e:
        print(f"Database initialization failed: {e}")
        raise
    finally:
        conn.close()

def migrate_db(conn, existing_tables):
    """Handle database schema migrations for existing databases"""
    print("Running database migrations...")
    
    # Create sessions table if it doesn't exist
    if 'sessions' not in existing_tables:
        conn.execute("""
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                start_time TEXT DEFAULT CURRENT_TIMESTAMP,
                end_time TEXT,
                interface TEXT,
                total_packets INTEGER DEFAULT 0,
                total_predictions INTEGER DEFAULT 0,
                total_alerts INTEGER DEFAULT 0
            )
        """)
        print("Created sessions table")
    
    # Add session_id to packets table if it doesn't exist
    try:
        conn.execute("ALTER TABLE packets ADD COLUMN session_id TEXT")
        print("Added session_id to packets table")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add session_id to predictions table if it doesn't exist
    try:
        conn.execute("ALTER TABLE predictions ADD COLUMN session_id TEXT")
        print("Added session_id to predictions table")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add session_id to alerts table if it doesn't exist
    try:
        conn.execute("ALTER TABLE alerts ADD COLUMN session_id TEXT")
        print("Added session_id to alerts table")
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        # This updates any existing sessions that have UTC timestamps
        # to use the same format as new local timestamps
        conn.execute("""
            UPDATE sessions 
            SET start_time = datetime(start_time, 'localtime'),
                end_time = datetime(end_time, 'localtime')
            WHERE start_time LIKE '%-%' AND start_time NOT LIKE '%,%'
        """)
        print("Fixed existing session timestamps")
    except Exception as e:
        print(f"Could not fix existing timestamps: {e}")
    
    # Create indexes
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_predictions_session ON predictions(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_time ON sessions(start_time)"
    ]
    
    for index_sql in indexes:
        try:
            conn.execute(index_sql)
        except Exception as e:
            print(f"Could not create index: {e}")
    
    conn.commit()
    print("Database migrations completed")

def create_session(session_id, interface=None, start_time=None):
    """Create a new capture session"""
    conn = get_db()
    try:
        # Use provided start_time or current local time
        if start_time is None:
            start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        conn.execute(
            "INSERT INTO sessions (id, start_time, interface) VALUES (?, ?, ?)",
            (session_id, start_time, interface)
        )
        conn.commit()
        print(f"Created new session: {session_id} at {start_time}")
        return True
    except sqlite3.IntegrityError:
        print(f"Session {session_id} already exists")
        return False
    except Exception as e:
        print(f"Error creating session: {e}")
        return False
    finally:
        conn.close()

def end_session(session_id, packet_count=0, prediction_count=0, alert_count=0, session_logs=None):
    """End a capture session and update statistics"""
    conn = get_db()
    try:
        # Use local time in the same format as start time
        from datetime import datetime
        local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        conn.execute(
            """UPDATE sessions 
               SET end_time = ?, 
                   total_packets = ?, 
                   total_predictions = ?, 
                   total_alerts = ?
               WHERE id = ?""",
            (local_time, packet_count, prediction_count, alert_count, session_id)
        )
        conn.commit()
        print(f"Ended session {session_id} at {local_time}")

        # Generate report after session ends WITH LIVE LOGS
        save_session_report(session_id, session_logs)

        return True
    except Exception as e:
        print(f"Error ending session: {e}")
        return False
    finally:
        conn.close()
        
def save_session_report(session_id, session_logs=None):
    """Generate and save a summarized report of a completed session"""
    conn = get_db()
    try:
        # Get session info
        cur = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        session = cur.fetchone()
        if not session:
            print(f"⚠️ No session found for {session_id}")
            return False

        # Get prediction summary
        cur = conn.execute("""
            SELECT label, COUNT(*) as count 
            FROM predictions 
            WHERE session_id = ? 
            GROUP BY label
        """, (session_id,))
        prediction_summary = {row['label']: row['count'] for row in cur.fetchall()}

        # Get recent alerts
        cur = conn.execute("""
            SELECT severity, message, created_at 
            FROM alerts 
            WHERE session_id = ? 
            ORDER BY created_at DESC 
            LIMIT 20
        """, (session_id,))
        alerts = [dict(row) for row in cur.fetchall()]

        # Use local time for report generation
        local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Combine report data WITH LIVE LOGS
        report_data = {
            "session": dict(session),
            "predictions": prediction_summary,
            "alerts": alerts,
            "live_logs": session_logs or [],
            "generated_at": local_time  # Use local time instead of UTC
        }

        # Use local time for report creation
        conn.execute("""
            INSERT INTO reports (session_id, title, report_data, created_at)
            VALUES (?, ?, ?, ?)
        """, (session_id, f"Session Report {session_id}", json.dumps(report_data), local_time))

        conn.commit()
        print(f"Report saved for session {session_id} at {local_time} with {len(session_logs or [])} live logs")
        return True
    except Exception as e:
        print(f"Error saving report: {e}")
        return False
    finally:
        conn.close()

def get_current_session_stats(session_id):
    """Get statistics for the current session"""
    conn = get_db()
    try:
        # Get threat distribution for current session
        cur = conn.execute("""
            SELECT label, COUNT(*) as count 
            FROM predictions 
            WHERE session_id = ? 
            GROUP BY label
        """, (session_id,))
        threat_distribution = {row['label']: row['count'] for row in cur.fetchall()}
        
        # Get recent alerts for current session
        cur = conn.execute("""
            SELECT a.id, a.severity, a.message, a.created_at, p.label
            FROM alerts a
            JOIN predictions p ON a.prediction_id = p.id
            WHERE a.session_id = ?
            ORDER BY a.created_at DESC
            LIMIT 20
        """, (session_id,))
        recent_alerts = [
            {
                'id': row['id'],
                'severity': row['severity'],
                'message': row['message'],
                'timestamp': row['created_at'],
                'label': row['label']
            }
            for row in cur.fetchall()
        ]
        
        # Get session info
        cur = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        session_row = cur.fetchone()
        session_info = dict(session_row) if session_row else None
        
        return {
            'threat_distribution': threat_distribution,
            'recent_alerts': recent_alerts,
            'session_info': session_info
        }
    except Exception as e:
        print(f"Error getting session stats: {e}")
        return {'threat_distribution': {}, 'recent_alerts': [], 'session_info': None}
    finally:
        conn.close()

def get_recent_sessions(limit=5):
    """Get recent capture sessions"""
    conn = get_db()
    try:
        cur = conn.execute("""
            SELECT * FROM sessions 
            ORDER BY start_time DESC 
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        print(f"Error getting recent sessions: {e}")
        return []
    finally:
        conn.close()

def save_metrics(name, value):
    """Save metrics (unchanged - safe to use)"""
    conn = get_db()
    try:
        conn.execute("INSERT INTO metrics (name, value) VALUES (?, ?)", (name, str(value)))
        conn.commit()
    except Exception as e:
        print(f"Error saving metric: {e}")
    finally:
        conn.close()

def save_model_info(name, dataset, path, size_kb, feature_names=None, label_classes=None, model_type=None):
    """Save model metadata in DB (updated to support model_type)"""
    conn = get_db()
    feature_names_json = json.dumps(feature_names) if feature_names else None
    label_classes_json = json.dumps(label_classes) if label_classes else None
    
    try:
        # Check if model_type column exists, if not add it
        try:
            conn.execute("ALTER TABLE models ADD COLUMN model_type TEXT")
            print("Added model_type column to models table")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        conn.execute("""
            INSERT INTO models (name, dataset, path, size_kb, feature_names_json, label_classes_json, model_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (name, dataset, str(path), size_kb, feature_names_json, label_classes_json, model_type))
        conn.commit()
        print(f"Model info saved: {name} ({model_type})")
    except Exception as e:
        print(f"Error saving model info: {e}")
    finally:
        conn.close()