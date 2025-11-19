import sqlite3
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "checks_metadata.db"


def get_check_metadata(check_id: str) -> Optional[dict]:
    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"Checks metadata database not found at {DB_PATH}. "
            "Please ensure the database file is included in the installation."
        )

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM check_metadata WHERE check_id = ?", (check_id,))

    row = cursor.fetchone()
    conn.close()

    if row:
        return dict(row)
    return None


def get_all_checks_metadata() -> list[dict]:
    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"Checks metadata database not found at {DB_PATH}. "
            "Please ensure the database file is included in the installation."
        )

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM check_metadata ORDER BY check_id")

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]
