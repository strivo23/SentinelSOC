"""Tolerant parser for common Linux sshd/auth.log messages."""
from datetime import datetime
import hashlib
import re

SYSLOG = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?P<msg>.*)$")
IP = r"(?:\d{1,3}\.){3}\d{1,3}"


def parse_line(line, year=None):
    raw = line.rstrip("\r\n")
    m = SYSLOG.match(raw)
    if not m:
        return None
    try:
        stamp = datetime.strptime(f"{year or datetime.now().year} {m['stamp']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    msg = m["msg"]
    record = {"timestamp": stamp.isoformat(sep=" "), "hostname": m["host"],
              "process": m["proc"].strip(), "username": None, "source_ip": None,
              "outcome": "other", "is_invalid_user": False, "raw_line": raw}
    invalid = re.search(r"Invalid user\s+(\S+)", msg)
    failed = re.search(r"Failed password for (?:invalid user )?(\S+) from (" + IP + r")", msg)
    accepted = re.search(r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) for (\S+) from (" + IP + r")", msg)
    if invalid:
        record.update(username=invalid.group(1), is_invalid_user=True, outcome="failed")
        source = re.search(r"from\s+(" + IP + r")", msg)
        if source: record["source_ip"] = source.group(1)
    if failed:
        record.update(username=failed.group(1), source_ip=failed.group(2), outcome="failed")
        if "invalid user" in msg: record["is_invalid_user"] = True
    elif accepted:
        record.update(username=accepted.group(1), source_ip=accepted.group(2), outcome="success")
    elif "authentication failure" in msg.lower():
        user = re.search(r"\buser=(\S+)", msg)
        source = re.search(r"\brhost=(" + IP + r")", msg)
        record["outcome"] = "failed"
        if user: record["username"] = user.group(1)
        if source: record["source_ip"] = source.group(1)
    record["fingerprint"] = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
    return record


def parse_lines(lines, year=None):
    """Malformed lines are skipped; exact duplicates are emitted once."""
    seen, events = set(), []
    for line in lines:
        try: event = parse_line(line, year=year)
        except (ValueError, TypeError, OverflowError): event = None
        if event and event["fingerprint"] not in seen:
            seen.add(event["fingerprint"]); events.append(event)
    return events
