"""Explainable rolling-window detections. Alerts indicate suspicious behavior, not proof of compromise."""
from datetime import datetime, timedelta
import hashlib


def detect(events, rules=None):
    cfg = {"brute_force_threshold":5,"window_minutes":5,"multi_username_threshold":4,
           "invalid_user_threshold":3,"burst_threshold":8}
    cfg.update(rules or {})
    ordered = sorted(events, key=lambda e: e["timestamp"])
    groups = {}
    for e in ordered:
        if e.get("source_ip"): groups.setdefault(e["source_ip"], []).append(e)
    alerts, seen = [], set()
    def add(category, severity, description, rows, ip, user=None):
        ids = sorted(e.get("id", e["fingerprint"]) for e in rows)
        key = f"{category}|{ip}|{ids[0]}|{ids[-1]}"
        fp = hashlib.sha256(key.encode()).hexdigest()
        if fp in seen: return
        seen.add(fp)
        alerts.append({"fingerprint":fp,"created_at":rows[-1]["timestamp"],"source_ip":ip,
                       "username":user,"category":category,"severity":severity,
                       "description":description,"event_ids":[e.get("id") for e in rows if e.get("id")]})
    for ip, rows in groups.items():
        failures = [e for e in rows if e["outcome"] == "failed"]
        window = timedelta(minutes=cfg["window_minutes"])
        brute_force_alerted = False
        burst_alerted = False
        left = 0
        failure_times = [datetime.fromisoformat(e["timestamp"]) for e in failures]
        for i, end in enumerate(failures):
            while left <= i and failure_times[i] - failure_times[left] > window:
                left += 1
            window_count = i - left + 1
            if window_count >= cfg["brute_force_threshold"] and not brute_force_alerted:
                subset = failures[left:i + 1]
                add("SSH Brute-Force","HIGH",f"{len(subset)} failed SSH attempts within {cfg['window_minutes']} minutes.",subset,ip)
                brute_force_alerted = True
            if window_count >= cfg["burst_threshold"] and not burst_alerted:
                subset = failures[left:i + 1]
                add("Suspicious Authentication Pattern","MEDIUM",f"Unusual burst of {len(subset)} failed authentications.",subset,ip)
                burst_alerted = True
        names = {e.get("username") for e in rows if e.get("username")}
        if len(names) >= cfg["multi_username_threshold"]:
            add("Multiple Username Attack","MEDIUM",f"Source attempted {len(names)} distinct usernames.",rows,ip)
        invalids = [e for e in failures if e.get("is_invalid_user")]
        if len(invalids) >= cfg["invalid_user_threshold"]:
            add("Invalid User Enumeration","MEDIUM",f"{len(invalids)} attempts targeted invalid usernames.",invalids,ip)
        for success in (e for e in rows if e["outcome"] == "success"):
            before = [e for e in failures if timedelta(0) <= datetime.fromisoformat(success["timestamp"])-datetime.fromisoformat(e["timestamp"]) <= window]
            if len(before) >= 2:
                add("Suspicious Login Activity","HIGH",f"Successful login followed {len(before)} failures from the same IP.",before+[success],ip,success.get("username"))
                break
    return alerts
