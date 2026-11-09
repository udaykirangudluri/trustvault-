import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "trustvault.db"


def get_db():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def init_db():
    connection = get_db()

    try:
        connection.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer'
                CHECK(role IN ('admin', 'owner', 'viewer')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            content_type TEXT,
            size INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            permission TEXT NOT NULL CHECK(permission IN ('read')),
            UNIQUE(document_id, user_id),
            FOREIGN KEY(document_id) REFERENCES documents(id)
                ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER,
            document_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(actor_id) REFERENCES users(id),
            FOREIGN KEY(document_id) REFERENCES documents(id)
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            username TEXT PRIMARY KEY,
            attempts INTEGER NOT NULL DEFAULT 0,
            window_started_at INTEGER NOT NULL,
            locked_until INTEGER NOT NULL DEFAULT 0
        );
        """)

        connection.commit()

    finally:
        connection.close()


if __name__ == "__main__":
    init_db()
    print("TrustVault database initialized successfully!")