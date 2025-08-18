from app.storage.db import init_db

if __name__ == "__main__":
    init_db()
    print("SQLite DB initialized (lai_ids.sqlite3)")