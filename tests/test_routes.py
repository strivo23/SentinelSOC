import io
from app import create_app
from database.db import query

def token(client):
    client.get("/")
    with client.session_transaction() as s:return s["csrf_token"]

def test_routes_upload_status_reports_and_404(tmp_path):
    app=create_app({"TESTING":True,"SECRET_KEY":"test","DATABASE":str(tmp_path/"test.db"),"UPLOAD_FOLDER":str(tmp_path),"DETECTION":{"brute_force_threshold":2,"window_minutes":5,"multi_username_threshold":4,"invalid_user_threshold":3,"burst_threshold":8}})
    c=app.test_client();assert c.get("/").status_code==200
    csrf=token(c)
    log="Feb 14 09:00:00 host sshd[1]: Failed password for admin from 203.0.113.1 port 44 ssh2\nFeb 14 09:01:00 host sshd[1]: Failed password for admin from 203.0.113.1 port 44 ssh2"
    response=c.post("/upload",data={"csrf_token":csrf,"logfile":(io.BytesIO(log.encode()),"test.log")},content_type="multipart/form-data")
    assert response.status_code==302
    assert c.get("/events").status_code==200 and c.get("/alerts").status_code==200 and c.get("/reports").status_code==200
    assert c.get("/reports/failed.csv").status_code==200
    evaluated=c.post("/reports",data={"csrf_token":csrf})
    assert evaluated.status_code==200 and b"DETECTION RATE" in evaluated.data
    alert=query(app.config["DATABASE"],"SELECT id FROM alerts")[0]
    assert c.post(f"/alerts/{alert['id']}/status",data={"csrf_token":csrf,"status":"Investigating"}).status_code==302
    assert c.get("/alerts/99999").status_code==404

def test_upload_rejects_invalid_extension_and_csrf(tmp_path):
    app=create_app({"TESTING":True,"SECRET_KEY":"test","DATABASE":str(tmp_path/"test.db"),"UPLOAD_FOLDER":str(tmp_path)})
    c=app.test_client();csrf=token(c)
    assert c.post("/upload",data={"csrf_token":csrf,"logfile":(io.BytesIO(b"x"),"x.exe")}).status_code==400
    assert c.post("/upload",data={"logfile":(io.BytesIO(b"x"),"x.log")}).status_code==400
