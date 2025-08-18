import sqlite3
conn = sqlite3.connect("lai_ids.sqlite3")
cur = conn.cursor()

# List all tables
cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
print(cur.fetchall())
