"""SentinelSOC Flask application."""
import csv
import io
import json
import os
import secrets
from datetime import date
import pandas as pd
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from config import Config
from database.db import initialize, query, update_status
from core.event_processor import process_log
from core.evaluation import evaluate


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config: app.config.update(test_config)
    app.config["DETECTION"] = dict(app.config["DETECTION"])
    initialize(app.config["DATABASE"])
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    @app.before_request
    def csrf_check():
        if request.method == "POST":
            token = session.get("csrf_token")
            supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not token or not secrets.compare_digest(token, supplied or ""):
                abort(400, "Invalid CSRF token")

    @app.context_processor
    def csrf_context():
        if "csrf_token" not in session: session["csrf_token"] = secrets.token_urlsafe(24)
        return {"csrf_token":session["csrf_token"]}

    @app.get("/")
    def dashboard():
        events = query(app.config["DATABASE"], "SELECT * FROM events ORDER BY timestamp DESC LIMIT 500")
        alerts = query(app.config["DATABASE"], "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 10")
        all_alerts = query(app.config["DATABASE"], "SELECT * FROM alerts")
        outcome_counts={r["outcome"]:r["n"] for r in query(app.config["DATABASE"],"SELECT outcome,COUNT(*) AS n FROM events GROUP BY outcome")}
        counts = {"events":sum(outcome_counts.values()),
                  "failed":outcome_counts.get("failed",0),"success":outcome_counts.get("success",0),
                  "alerts":len(all_alerts),"high":sum(a["severity"] in ("HIGH","CRITICAL") for a in all_alerts),
                  "ips":len({a["source_ip"] for a in all_alerts if a["source_ip"]})}
        activity = list(reversed(events[:30]))
        chart = {"labels":[e["timestamp"] for e in activity],
                 "failed":[int(e["outcome"]=="failed") for e in activity],
                 "success":[int(e["outcome"]=="success") for e in activity]}
        severities={s:sum(a["severity"]==s for a in all_alerts) for s in ["HIGH","MEDIUM","LOW","CRITICAL"]}
        categories={}
        for a in all_alerts: categories[a["category"]]=categories.get(a["category"],0)+1
        tops={}
        for a in all_alerts:
            if a["source_ip"]: tops[a["source_ip"]]=tops.get(a["source_ip"],0)+1
        return render_template("dashboard.html", counts=counts, alerts=alerts, chart=chart,
                               severities=severities,categories=categories,tops=dict(sorted(tops.items(),key=lambda x:-x[1])[:5]))

    @app.get("/events")
    def events_page():
        return render_template("events.html", events=filtered_rows("events"))

    @app.get("/alerts")
    def alerts_page():
        return render_template("alerts.html", alerts=filtered_rows("alerts"))

    def filtered_rows(table):
        page=max(1,request.args.get("page",1,type=int)); size=50
        where=[]; params=[]
        search=request.args.get("q","").strip()
        if search:
            where.append("(source_ip LIKE ? OR username LIKE ? OR description LIKE ? OR category LIKE ?)")
            params.extend([f"%{search}%"]*4)
        severity=request.args.get("severity","")
        if table=="alerts" and severity: where.append("severity=?");params.append(severity)
        category=request.args.get("category","")
        if table=="alerts" and category: where.append("category=?");params.append(category)
        outcome=request.args.get("outcome","")
        if table=="events" and outcome: where.append("outcome=?");params.append(outcome)
        sql=f"SELECT * FROM {table}"+(" WHERE "+" AND ".join(where) if where else "")+f" ORDER BY {'timestamp' if table=='events' else 'created_at'} DESC LIMIT ? OFFSET ?"
        rows=query(app.config["DATABASE"],sql,params+[size,(page-1)*size])
        total=query(app.config["DATABASE"],f"SELECT COUNT(*) AS n FROM {table}"+(" WHERE "+" AND ".join(where) if where else ""),params)[0]["n"]
        return {"rows":rows,"page":page,"pages":max(1,(total+size-1)//size),"total":total}

    @app.get("/alerts/<int:alert_id>")
    def alert_details(alert_id):
        rows=query(app.config["DATABASE"],"SELECT * FROM alerts WHERE id=?",(alert_id,))
        if not rows: abort(404)
        alert=rows[0]
        ids=json.loads(alert["event_ids"])
        related=[]
        if ids: related=query(app.config["DATABASE"],f"SELECT * FROM events WHERE id IN ({','.join('?' for _ in ids)}) ORDER BY timestamp",ids)
        return render_template("alert_details.html",alert=alert,events=related)

    @app.post("/alerts/<int:alert_id>/status")
    def set_status(alert_id):
        status=request.form.get("status","")
        if status not in {"New","Investigating","Resolved"}: abort(400)
        if not update_status(app.config["DATABASE"],alert_id,status): abort(404)
        flash("Alert status updated.","success"); return redirect(url_for("alert_details",alert_id=alert_id))

    @app.get("/ip/<path:ip>")
    def ip_details(ip):
        rows=query(app.config["DATABASE"],"SELECT * FROM events WHERE source_ip=? ORDER BY timestamp DESC LIMIT 250",(ip,))
        alerts=query(app.config["DATABASE"],"SELECT * FROM alerts WHERE source_ip=? ORDER BY created_at DESC",(ip,))
        return render_template("ip_details.html",ip=ip,events=rows,alerts=alerts)

    @app.route("/settings",methods=["GET","POST"])
    def settings():
        if request.method=="POST":
            try:
                for key in app.config["DETECTION"]:
                    value=int(request.form[key])
                    if not 1<=value<=10000: raise ValueError
                    app.config["DETECTION"][key]=value
            except (ValueError,KeyError): abort(400,"Thresholds must be integers between 1 and 10000")
            flash("Detection thresholds saved for this run.","success"); return redirect(url_for("settings"))
        return render_template("settings.html",rules=app.config["DETECTION"])

    @app.route("/reports",methods=["GET","POST"])
    def reports():
        metrics=None
        if request.method=="POST":
            labels=[]
            truth=os.path.join(os.path.dirname(__file__),"data","ground_truth.csv")
            with open(truth,encoding="utf-8",newline="") as f:
                for r in csv.DictReader(f): labels.append({"scenario_id":r["scenario_id"],"ground_truth":r["ground_truth"].lower()=="true"})
            predictions={r["scenario_id"]:r["detected"].lower()=="true" for r in csv.DictReader(open(os.path.join(os.path.dirname(__file__),"data","evaluation_predictions.csv"),encoding="utf-8"))}
            metrics=evaluate(labels,predictions)
        return render_template("reports.html",metrics=metrics)

    @app.get("/reports/<kind>.csv")
    def export_csv(kind):
        mapping={"events":"events","failed":"events","successful":"events","alerts":"alerts","high":"alerts"}
        if kind not in mapping: abort(404)
        table=mapping[kind]; where=[]; params=[]
        start=request.args.get("start",""); end=request.args.get("end","")
        timecol="timestamp" if table=="events" else "created_at"
        if start: where.append(f"date({timecol})>=date(?)");params.append(start)
        if end: where.append(f"date({timecol})<=date(?)");params.append(end)
        if kind=="failed": where.append("outcome='failed'")
        if kind=="successful": where.append("outcome='success'")
        if kind=="high": where.append("severity IN ('HIGH','CRITICAL')")
        sql=f"SELECT * FROM {table}"+(" WHERE "+" AND ".join(where) if where else "")+f" ORDER BY {timecol} DESC"
        rows=query(app.config["DATABASE"],sql,params)
        columns=list(rows[0].keys()) if rows else (["id","timestamp","source_ip","username","outcome","raw_line"] if table=="events" else ["id","created_at","source_ip","username","category","severity","description","status"])
        frame=pd.DataFrame(rows,columns=columns)
        payload=frame.to_csv(index=False).encode("utf-8-sig")
        return send_file(io.BytesIO(payload),mimetype="text/csv",as_attachment=True,download_name=f"sentinelsoc_{kind}_{date.today().isoformat()}.csv")

    @app.route("/upload",methods=["GET","POST"])
    def upload():
        if request.method=="POST":
            f=request.files.get("logfile")
            if not f or not f.filename or "." not in f.filename or f.filename.rsplit(".",1)[1].lower() not in app.config["ALLOWED_EXTENSIONS"]:
                abort(400,"Choose a .log or .txt authentication log")
            content=f.stream.read(app.config["MAX_CONTENT_LENGTH"]+1)
            if len(content)>app.config["MAX_CONTENT_LENGTH"]: abort(413)
            try: lines=content.decode("utf-8-sig",errors="replace").splitlines()
            except Exception: abort(400,"Could not read uploaded log")
            result=process_log(lines,app.config["DATABASE"],app.config["DETECTION"])
            flash(f"Parsed {result['parsed']} events; added {result['inserted']} new events and {result['alerts']} alerts.","success")
            return redirect(url_for("dashboard"))
        return render_template("upload.html")

    @app.get("/api/dashboard")
    def dashboard_api():
        return jsonify(query(app.config["DATABASE"],"SELECT outcome,COUNT(*) AS count FROM events GROUP BY outcome"))

    return app


app=create_app()
if __name__=="__main__":
    app.run(host="127.0.0.1",port=5000,debug=False)
