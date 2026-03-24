"""SQLite persistence for domain notebook, watchlist, and preferences."""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


def _default_db_path() -> Path:
    """Return the default database path, creating the directory if needed."""
    path = Path.home() / ".familiar" / "familiar.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


class Memory:
    """Persistent storage for Familiar's domain knowledge.

    Stores three kinds of data:
    - Domain notes: domains the user has investigated, with freeform notes and tags
    - Watchlist: domains to monitor for expiration, SSL, and DNS changes
    - Preferences: key-value settings (e.g., explanation mode)
    """

    def __init__(self, db_path: Path | None = None):
        self._db_path = db_path or _default_db_path()
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS domain_notes (
                    domain TEXT PRIMARY KEY,
                    notes TEXT NOT NULL DEFAULT '',
                    tags TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS watchlist (
                    domain TEXT PRIMARY KEY,
                    added TEXT NOT NULL,
                    last_checked TEXT,
                    last_status TEXT
                );
                CREATE TABLE IF NOT EXISTS preferences (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            """)
            self._conn.commit()

    # --- Domain Notebook ---

    def remember_domain(self, domain: str, notes: str = "", tags: str = "") -> dict:
        """Save or update a domain in the notebook. Appends notes, merges tags."""
        now = datetime.now(timezone.utc).isoformat()
        domain = domain.lower().strip()
        with self._lock:
            existing = self._conn.execute(
                "SELECT * FROM domain_notes WHERE domain = ?", (domain,)
            ).fetchone()
            if existing:
                current_notes = existing["notes"]
                merged_notes = f"{current_notes}\n{notes}".strip() if notes else current_notes
                current_tags = set(filter(None, existing["tags"].split(",")))
                new_tags = set(filter(None, tags.split(",")))
                merged_tags = ",".join(sorted(current_tags | new_tags))
                self._conn.execute(
                    "UPDATE domain_notes SET notes = ?, tags = ?, last_seen = ? WHERE domain = ?",
                    (merged_notes, merged_tags, now, domain),
                )
            else:
                self._conn.execute(
                    "INSERT INTO domain_notes (domain, notes, tags, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (domain, notes, tags, now, now),
                )
            self._conn.commit()
            return self._get_domain_note_unlocked(domain)

    def recall_domain(self, domain: str) -> dict | None:
        """Retrieve notes for a specific domain."""
        with self._lock:
            return self._get_domain_note_unlocked(domain.lower().strip())

    def recall_all_domains(self) -> list[dict]:
        """List all domains in the notebook, most recently seen first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM domain_notes ORDER BY last_seen DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def tag_search(self, tag: str) -> list[dict]:
        """Search for domains matching a tag (exact, case-insensitive)."""
        tag = tag.strip().lower()
        # Escape LIKE wildcards to prevent unintended pattern matching
        escaped_tag = tag.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM domain_notes WHERE tags LIKE ? ESCAPE '\\' ORDER BY last_seen DESC",
                (f"%{escaped_tag}%",),
            ).fetchall()
            # Filter to exact tag matches (SQL LIKE is a coarse pre-filter)
            return [
                {
                    "domain": r["domain"],
                    "notes": r["notes"],
                    "tags": r["tags"],
                    "first_seen": r["first_seen"],
                    "last_updated": r["last_seen"],
                }
                for r in rows
                if tag in [t.strip().lower() for t in r["tags"].split(",")]
            ]

    def _get_domain_note_unlocked(self, domain: str) -> dict | None:
        """Internal helper — caller must hold self._lock."""
        row = self._conn.execute(
            "SELECT * FROM domain_notes WHERE domain = ?", (domain,)
        ).fetchone()
        return dict(row) if row else None

    # --- Watchlist ---

    def watchlist_add(self, domain: str) -> dict:
        """Add a domain to the watchlist."""
        now = datetime.now(timezone.utc).isoformat()
        domain = domain.lower().strip()
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO watchlist (domain, added) VALUES (?, ?)",
                (domain, now),
            )
            self._conn.commit()
        return {"domain": domain, "added": now, "status": "added"}

    def watchlist_remove(self, domain: str) -> dict:
        """Remove a domain from the watchlist."""
        domain = domain.lower().strip()
        with self._lock:
            cursor = self._conn.execute("DELETE FROM watchlist WHERE domain = ?", (domain,))
            self._conn.commit()
            status = "removed" if cursor.rowcount > 0 else "not_found"
        return {"domain": domain, "status": status}

    def watchlist_list(self) -> list[dict]:
        """List all watched domains."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM watchlist ORDER BY added DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def watchlist_update_status(self, domain: str, status: dict) -> None:
        """Update the last check status for a watched domain."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE watchlist SET last_checked = ?, last_status = ? WHERE domain = ?",
                (now, json.dumps(status, default=str), domain),
            )
            self._conn.commit()

    # --- Preferences ---

    def get_preference(self, key: str, default: str = "") -> str:
        """Get a preference value."""
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM preferences WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else default

    def set_preference(self, key: str, value: str) -> None:
        """Set a preference value."""
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO preferences (key, value) VALUES (?, ?)",
                (key, value),
            )
            self._conn.commit()

    def close(self):
        """Close the database connection."""
        with self._lock:
            self._conn.close()
