CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL UNIQUE,
 timestamp TEXT NOT NULL, hostname TEXT, process TEXT, username TEXT,
 source_ip TEXT, outcome TEXT NOT NULL, is_invalid_user INTEGER NOT NULL DEFAULT 0,
 raw_line TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL, source_ip TEXT, username TEXT, category TEXT NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
 description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New'
 CHECK(status IN ('New','Investigating','Resolved')), event_ids TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
