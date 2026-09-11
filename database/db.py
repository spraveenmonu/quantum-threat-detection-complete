import sqlite3
import os
import shutil

# Store database in hidden .data/ directory so local dev watchers (e.g. VS Code Live Server)
# do NOT detect database writes and trigger unintended browser auto-reloads.
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".data")
os.makedirs(DATA_DIR, exist_ok=True)
DB = os.path.join(DATA_DIR, "quantum_security.db")

# Migrate existing database if needed
OLD_DB = os.path.join(os.path.dirname(__file__), "quantum_security.db")
if os.path.exists(OLD_DB) and not os.path.exists(DB):
    try:
        shutil.copy2(OLD_DB, DB)
    except Exception:
        pass


def conn():
    """Create a new database connection with Row factory."""
    c = sqlite3.connect(DB, timeout=15, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    """Initialize database tables if they don't exist."""
    with conn() as c:
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("""CREATE TABLE IF NOT EXISTS signatures (
            session_id TEXT PRIMARY KEY,
            message TEXT NOT NULL,
            message_hash TEXT NOT NULL,
            signer TEXT NOT NULL,
            bell_state TEXT NOT NULL,
            pauli_correction TEXT NOT NULL,
            measurement_match REAL NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            category TEXT NOT NULL,
            actor TEXT,
            decision TEXT NOT NULL,
            threat_score REAL NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        )""")


def execute(sql, params=()):
    """Execute a write query (INSERT/UPDATE/DELETE)."""
    with conn() as c:
        c.execute(sql, params)
        c.commit()


def one(sql, params=()):
    """Fetch a single row."""
    with conn() as c:
        return c.execute(sql, params).fetchone()


def all_rows(sql, params=()):
    """Fetch all rows."""
    with conn() as c:
        return c.execute(sql, params).fetchall()


def get_metrics():
    """Calculate dashboard metrics with corrected formulas."""
    total = one("SELECT COUNT(*) n FROM signatures")["n"]
    attacks = one(
        "SELECT COUNT(*) n FROM events WHERE category != 'LEGITIMATE' AND decision='REJECT'"
    )["n"]
    legit = one(
        "SELECT COUNT(*) n FROM events WHERE category='LEGITIMATE' AND decision='ACCEPT'"
    )["n"]
    total_events = one("SELECT COUNT(*) n FROM events")["n"]
    accepted = one("SELECT COUNT(*) n FROM events WHERE decision='ACCEPT'")["n"]

    # Fix: detection_rate should be attacks detected out of total threat events
    # (not attacks/max(attacks,1) which is always 100%)
    threat_events = attacks + legit  # total events that were evaluated
    return {
        "total_signatures": total,
        "attacks_detected": attacks,
        "legitimate_verifications": legit,
        "verification_accuracy": (
            round((accepted / total_events * 100), 2) if total_events else 0
        ),
        "detection_rate": (
            round((attacks / threat_events * 100), 2) if threat_events else 0
        ),
        "total_events": total_events,
    }


def list_events(limit=20):
    """List recent events in descending order."""
    rows = all_rows("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    return [dict(r) for r in rows]
