from database.db import initialize,insert_events,insert_alerts,query

def test_event_and_alert_duplicate_prevention(tmp_path):
    path=str(tmp_path/"test.db");initialize(path)
    event={"fingerprint":"abc","timestamp":"2025-01-01 00:00:00","hostname":"h","process":"sshd","username":"u","source_ip":"192.0.2.1","outcome":"failed","raw_line":"line"}
    assert insert_events(path,[event,event])==1
    assert len(query(path,"SELECT * FROM events"))==1
    alert={"fingerprint":"fp","created_at":event["timestamp"],"source_ip":event["source_ip"],"category":"test","severity":"HIGH","description":"detail"}
    assert insert_alerts(path,[alert,alert])==1
