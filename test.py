import sqlite3

db_path = "lai_ids.sqlite3"  # adjust if path is different
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Add timestamp column if not exists
cur.execute("PRAGMA table_info(models)")
columns = [row[1] for row in cur.fetchall()]
if "timestamp" not in columns:
    cur.execute("ALTER TABLE models ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP")
    print("✅ Timestamp column added.")
else:
    print("ℹ️ Timestamp column already exists.")

conn.commit()
conn.close()
