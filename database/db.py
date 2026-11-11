"""Small parameterized SQLite data access layer."""
import json
import sqlite3
from pathlib import Path


def connect(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def initialize(path):
    with connect(path) as db:
        db.executescript(Path(__file__).with_name("schema.sql").read_text(encoding="utf-8"))


def insert_events(path, events):
    inserted = 0
    with connect(path) as db:
        for e in events:
            cur = db.execute("""INSERT OR IGNORE INTO events
              (fingerprint,timestamp,hostname,process,username,source_ip,outcome,is_invalid_user,raw_line)
              VALUES(?,?,?,?,?,?,?,?,?)""", (e["fingerprint"], e["timestamp"], e.get("hostname"),
              e.get("process"), e.get("username"), e.get("source_ip"), e["outcome"],
              int(e.get("is_invalid_user", False)), e["raw_line"]))
            inserted += cur.rowcount
    return inserted


def insert_alerts(path, alerts):
    count = 0
    with connect(path) as db:
        for a in alerts:
            cur = db.execute("""INSERT OR IGNORE INTO alerts
              (fingerprint,created_at,source_ip,username,category,severity,description,event_ids)
              VALUES(?,?,?,?,?,?,?,?)""", (a["fingerprint"],a["created_at"],a.get("source_ip"),
              a.get("username"),a["category"],a["severity"],a["description"],json.dumps(a.get("event_ids",[]))))
            count += cur.rowcount
    return count


def query(path, sql, params=()):
    with connect(path) as db:
        return [dict(r) for r in db.execute(sql, params).fetchall()]


def update_status(path, alert_id, status):
    with connect(path) as db:
        cur = db.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
        return cur.rowcount == 1
