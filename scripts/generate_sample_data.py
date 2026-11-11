"""Generate deterministic, synthetic auth.log and labelled scenario evaluation data."""
import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from core.log_parser import parse_lines
from core.detection_engine import detect

BASE=datetime(2025,2,14,9,0,0)
scenarios=[]
def record(sid, ip, username, outcome, minute, second=0, invalid=False):
    stamp=BASE+timedelta(minutes=minute,seconds=second)
    if outcome=="success": msg=f"Accepted publickey for {username} from {ip} port 2202 ssh2"
    elif invalid: msg=f"Invalid user {username} from {ip} port 4022"
    else: msg=f"Failed password for {username} from {ip} port 4022 ssh2"
    line=f"{stamp:%b %d %H:%M:%S} lab-host sshd[2200]: {msg}"
    scenarios.append((sid,ip,outcome,line))

for i,(u,minute) in enumerate([("analyst",0),("operator",2),("analyst",4)]): record("normal", "192.0.2.10",u,"success",minute,i)
record("normal","198.51.100.20","operator","failed",5,5)
record("normal","198.51.100.20","operator","success",8,2)
for i in range(5): record("brute_force","203.0.113.40","admin","failed",10,i*30)
for i,u in enumerate(["admin","root","guest","oracle"]): record("multi_username","203.0.113.41",u,"failed",20,i*35)
for i,u in enumerate(["baduser","nobody","testghost"]): record("invalid_enum","203.0.113.42",u,"failed",30,i*40,True)
record("failure_then_success","198.51.100.55","analyst","failed",40,0)
record("failure_then_success","198.51.100.55","analyst","failed",40,30)
record("failure_then_success","198.51.100.55","analyst","success",41,0)
scenarios.sort(key=lambda x:x[3])
log_path=ROOT/"data"/"sample_auth.log"; log_path.parent.mkdir(exist_ok=True)
log_path.write_text("\n".join(row[3] for row in scenarios)+"\n",encoding="utf-8")
events=parse_lines(log_path.read_text(encoding="utf-8").splitlines(),year=2025)
alerts=detect(events)
by_ip={}
for _,ip,_,_ in scenarios: by_ip.setdefault(ip,False)
for a in alerts:
    if a["source_ip"] in by_ip: by_ip[a["source_ip"]]=True
labels=[("normal",False,"192.0.2.10"),("brute_force",True,"203.0.113.40"),
        ("multi_username",True,"203.0.113.41"),("invalid_enum",True,"203.0.113.42"),
        ("failure_then_success",True,"198.51.100.55")]
with open(ROOT/"data"/"ground_truth.csv","w",newline="",encoding="utf-8") as f:
    w=csv.writer(f);w.writerow(["scenario_id","source_ip","ground_truth"])
    for sid,actual,ip in labels:w.writerow([sid,ip,str(actual).lower()])
with open(ROOT/"data"/"evaluation_predictions.csv","w",newline="",encoding="utf-8") as f:
    w=csv.writer(f);w.writerow(["scenario_id","detected"])
    for sid,_,ip in labels:w.writerow([sid,str(by_ip[ip]).lower()])
print(f"Generated {len(events)} synthetic events and {len(alerts)} alerts across {len(labels)} labelled scenarios.")
