"""Coordinates parse, idempotent persistence and detection."""
from .log_parser import parse_lines
from .detection_engine import detect
from database.db import insert_events, insert_alerts


def process_log(lines, db_path, rules=None, year=None):
    events = parse_lines(lines, year=year)
    inserted = insert_events(db_path, events)
    alerts = detect(events, rules)
    alert_count = insert_alerts(db_path, alerts)
    return {"parsed":len(events),"inserted":inserted,"alerts":alert_count,"alert_records":alerts}
