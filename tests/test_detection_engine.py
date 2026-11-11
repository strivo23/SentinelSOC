from datetime import datetime,timedelta
from core.detection_engine import detect

def ev(i,ip="203.0.113.7",user="admin",outcome="failed",invalid=False):
    return {"timestamp":(datetime(2025,1,1)+timedelta(seconds=i*20)).isoformat(sep=" "),"source_ip":ip,"username":user,"outcome":outcome,"is_invalid_user":invalid,"fingerprint":str(i)}

def test_bruteforce_threshold_and_dedup():
    rows=[ev(i) for i in range(5)]
    alerts=detect(rows)
    assert any(a["category"]=="SSH Brute-Force" and a["severity"]=="HIGH" for a in alerts)
    assert any(a["category"]=="SSH Brute-Force" for a in detect(rows+[ev(5)]))
    assert detect(rows)==alerts
    assert not any(a["category"]=="SSH Brute-Force" for a in detect(rows[:4]))

def test_multiple_users_invalid_and_success_after_failures():
    many=[ev(i,user=u) for i,u in enumerate(["a","b","c","d"])]
    assert any(a["category"]=="Multiple Username Attack" for a in detect(many))
    invalid=[ev(i,user=f"bad{i}",invalid=True) for i in range(3)]
    assert any(a["category"]=="Invalid User Enumeration" for a in detect(invalid))
    seq=[ev(0),ev(1),ev(2,user="admin",outcome="success")]
    assert any(a["category"]=="Suspicious Login Activity" for a in detect(seq))

def test_normal_success_not_alert():
    assert detect([ev(1,outcome="success",ip="192.0.2.1")])==[]
