"""Scam Shield: local-first cyber-safety dashboard. Binds to 127.0.0.1 by default."""
import csv
import hmac
import io
import json
import re
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import config
import db
import make_samples
import runners
from services import (apk_metadata, iot_sim, login_monitor, qr_integrity, readiness, reconciliation,
                      secret_scanner, upi_risk, voice_safety)

UPI_ID_RE = qr_integrity.UPI_ID_RE
CSV_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def create_app(instance=None):
    app = Flask(__name__)
    inst = instance or config.instance_dir()
    inst.mkdir(parents=True, exist_ok=True)
    app.config.update(SECRET_KEY=config.load_secret_key(inst), DB_PATH=str(inst / "shield.db"),
                      MAX_CONTENT_LENGTH=config.MAX_UPLOAD, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
                      SAMPLE_LOG=str(config.SAMPLE / "auth_sample.log"), TESTING=False)
    db.init(app.config["DB_PATH"])
    throttle = {}

    # ---------- plumbing ----------
    @app.before_request
    def _open_db():
        g.db = db.connect(app.config["DB_PATH"])

    @app.teardown_request
    def _close_db(exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    @app.before_request
    def _csrf():
        if request.method in ("POST", "PUT", "DELETE"):
            tok = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            if not session.get("csrf") or not hmac.compare_digest(tok, session["csrf"]):
                return jsonify(ok=False, error="CSRF check failed. Reload the page."), 400

    @app.after_request
    def _headers(resp):
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data: blob:; style-src 'self'; "
                                                   "script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(self), microphone=()"
        if request.path.startswith("/api"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    def has_user():
        return g.db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None

    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("uid"):
                if request.path.startswith("/api"):
                    return jsonify(ok=False, error="Login required."), 401
                return redirect(url_for("login"))
            return fn(*a, **kw)
        return wrapper

    def body():
        return request.get_json(silent=True) or {}

    def bad(msg, code=400):
        return jsonify(ok=False, error=msg), code

    # ---------- auth ----------
    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if has_user():
            return redirect(url_for("login"))
        err = None
        if request.method == "POST":
            u, p = request.form.get("username", "").strip(), request.form.get("password", "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", u):
                err = "Username: 3-32 letters, digits, . _ -"
            elif len(p) < 8:
                err = "Password must be at least 8 characters."
            else:
                g.db.execute("INSERT INTO users(username,pw_hash) VALUES(?,?)", (u, generate_password_hash(p)))
                db.audit(g.db, "setup", u)
                g.db.commit()
                return redirect(url_for("login"))
        return render_template("login.html", mode="setup", error=err, csrf=csrf_token())

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not has_user():
            return redirect(url_for("setup"))
        err = None
        if request.method == "POST":
            ip = request.remote_addr or "?"
            fails, until = throttle.get(ip, (0, 0))
            if until > time.time():
                err = "Too many attempts. Wait a minute."
            else:
                row = g.db.execute("SELECT * FROM users WHERE username=?", (request.form.get("username", ""),)).fetchone()
                if row and check_password_hash(row["pw_hash"], request.form.get("password", "")):
                    throttle.pop(ip, None)
                    session.clear()
                    session.permanent = True
                    session["uid"] = row["id"]
                    csrf_token()
                    db.audit(g.db, "login", row["username"])
                    g.db.commit()
                    return redirect(url_for("dashboard"))
                fails += 1
                throttle[ip] = (fails, time.time() + 60 if fails >= 5 else 0)
                err = "Wrong username or password."
        return render_template("login.html", mode="login", error=err, csrf=csrf_token())

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def dashboard():
        return render_template("dashboard.html", csrf=csrf_token())

    @app.route("/api/health")
    def health():
        return jsonify(ok=True, version="1.0")

    # ---------- Engine A: messages, QR, payments ----------
    @app.post("/api/analyze")
    @login_required
    def api_analyze():
        text = str(body().get("text", ""))
        if len(text) > 5000:
            return bad("Text too long (5000 characters max).")
        res = upi_risk.analyze(text)
        if res["level"] in ("High", "Medium"):
            ids = ",".join(r["id"] for r in res["reasons"])
            db.add_alert(g.db, "message", ids or "U00", res["level"].lower(),
                         f"{res['level']} risk message/link detected", f"{res['level']} जोखिम वाला संदेश/लिंक मिला",
                         f"rules={ids}; length={len(text)}", "Message analyser (text not stored)", res["next_en"], res["next_hi"])
            g.db.commit()
        return jsonify(ok=True, **res)

    @app.route("/api/qr/registered", methods=["GET", "POST"])
    @login_required
    def api_qr_registered():
        if request.method == "POST":
            b = body()
            upi, name, label = str(b.get("upi_id", "")).strip(), str(b.get("payee_name", "")).strip()[:80], str(b.get("label", "Main counter")).strip()[:40]
            if not UPI_ID_RE.match(upi):
                return bad("UPI ID format looks wrong (example: shopname@bank).")
            g.db.execute("INSERT INTO registered_qrs(label,upi_id,payee_name,created) VALUES(?,?,?,?)", (label, upi, name, db.now_s()))
            db.audit(g.db, "qr_register", upi)
            g.db.commit()
        rows = [dict(r) for r in g.db.execute("SELECT id,label,upi_id,payee_name FROM registered_qrs")]
        return jsonify(ok=True, registered=rows)

    @app.post("/api/qr/delete")
    @login_required
    def api_qr_delete():
        g.db.execute("DELETE FROM registered_qrs WHERE id=?", (int(body().get("id", 0)),))
        g.db.commit()
        return jsonify(ok=True)

    @app.post("/api/qr/scan")
    @login_required
    def api_qr_scan():
        registered = [dict(r) for r in g.db.execute("SELECT label,upi_id,payee_name FROM registered_qrs")]
        if not registered:
            return bad("Register your shop's real UPI ID first.")
        payload = None
        f = request.files.get("image")
        if f:
            data = f.read(2_000_001)
            if len(data) > 2_000_000:
                return bad("Image too large (2 MB max).")
            if not (data[:8] == b"\x89PNG\r\n\x1a\n" or data[:3] == b"\xff\xd8\xff"):
                return bad("Only PNG or JPEG images are accepted.")
            payload = qr_integrity.decode_image(data)
        else:
            payload = str(body().get("payload", ""))[:2000] or None
        res = qr_integrity.compare(payload, registered)
        g.db.execute("INSERT INTO qr_scans(ts,status,observed,flags) VALUES(?,?,?,?)",
                     (db.now_s(), res["status"], str(res.get("observed", ""))[:80], ",".join(res["flags"])))
        if res["status"] != "MATCH":
            sev = "high" if res["status"] in ("MISMATCH", "PARTIAL", "NOT_UPI") else "medium"
            db.add_alert(g.db, "qr", res["status"], sev, f"QR check: {res['status'].replace('_', ' ').title()}", "QR जाँच: " + res["status"],
                         f"expected={','.join(res['expected'])} observed={res.get('observed')}", "QR integrity check",
                         res["en"], res["hi"])
        g.db.commit()
        return jsonify(ok=True, **res)

    @app.get("/api/qr/history")
    @login_required
    def api_qr_history():
        return jsonify(ok=True, history=[dict(r) for r in g.db.execute("SELECT ts,status,observed,flags FROM qr_scans ORDER BY id DESC LIMIT 20")])

    @app.route("/api/sales", methods=["GET", "POST"])
    @login_required
    def api_sales():
        if request.method == "POST":
            b = body()
            amt = reconciliation.parse_amount(str(b.get("amount", "")))
            if amt is None or amt <= 0 or amt > 10_000_000:
                return bad("Enter a valid amount.")
            ts = reconciliation.parse_ts(str(b.get("ts", ""))) if b.get("ts") else datetime.now()
            if ts is None:
                return bad("Time format not understood.")
            g.db.execute("INSERT INTO sales(ts,amount,ref,note) VALUES(?,?,?,?)",
                         (ts.strftime("%Y-%m-%d %H:%M:%S"), amt, str(b.get("ref", ""))[:40], str(b.get("note", ""))[:80]))
            g.db.commit()
        return jsonify(ok=True, sales=[dict(r) for r in g.db.execute("SELECT * FROM sales ORDER BY ts DESC LIMIT 100")])

    @app.post("/api/recon/import")
    @login_required
    def api_recon_import():
        f = request.files.get("file")
        if not f or not f.filename.lower().endswith(".csv"):
            return bad("Upload a .csv file.")
        raw = f.read(1_000_001)
        if len(raw) > 1_000_000:
            return bad("CSV too large (1 MB max).")
        rows, errors = reconciliation.parse_csv(raw)
        if not rows:
            return jsonify(ok=False, error="No usable rows.", errors=errors), 400
        batch = db.now_s()
        g.db.executemany("INSERT INTO transactions(batch,txn_id,ts,amount,status,reference,duplicate) VALUES(?,?,?,?,?,?,?)",
                         [(batch, r["txn_id"], r["ts"].strftime("%Y-%m-%d %H:%M:%S"), r["amount"], r["status"], r["reference"], int(r["duplicate"])) for r in rows])
        db.audit(g.db, "statement_import", f"{len(rows)} rows, {len(errors)} rejected")
        g.db.commit()
        return jsonify(ok=True, imported=len(rows), rejected=errors, duplicates=sum(1 for r in rows if r["duplicate"]), batch=batch)

    @app.get("/api/recon/run")
    @login_required
    def api_recon_run():
        latest = g.db.execute("SELECT MAX(batch) b FROM transactions").fetchone()["b"]
        if not latest:
            return bad("Import a statement CSV first (source of truth for the comparison).")
        txns = [{"txn_id": r["txn_id"], "ts": db.parse_s(r["ts"]), "amount": r["amount"], "status": r["status"],
                 "reference": r["reference"] or "", "duplicate": bool(r["duplicate"])}
                for r in g.db.execute("SELECT * FROM transactions WHERE batch=?", (latest,))]
        sales = [{"id": r["id"], "ts": db.parse_s(r["ts"]), "amount": r["amount"], "ref": r["ref"] or ""}
                 for r in g.db.execute("SELECT * FROM sales")]
        res = reconciliation.reconcile(sales, txns)
        g.db.execute("UPDATE alerts SET ack=1 WHERE module='payments' AND ack=0")
        for r in res["rows"]:
            if r["status"] == "UNMATCHED":
                db.add_alert(g.db, "payments", "P01", "high", f"Possible missing payment: Rs {r['amount']:.2f} at {r['ts']}",
                             f"संभावित गुम भुगतान: Rs {r['amount']:.2f}, {r['ts']}", f"sale#{r['sale_id']} not in statement {latest}",
                             f"Imported CSV ({latest})", r["en"], r["hi"])
            elif r["status"] == "AMBIGUOUS":
                db.add_alert(g.db, "payments", "P02", "medium", f"Ambiguous match for Rs {r['amount']:.2f}", f"Rs {r['amount']:.2f} का मिलान अस्पष्ट",
                             f"sale#{r['sale_id']} candidates={','.join(r['candidates'])}", f"Imported CSV ({latest})", r["en"], r["hi"])
        bad_n = res["summary"]["UNMATCHED"] + res["summary"]["AMBIGUOUS"]
        g.db.execute("INSERT INTO scans(ts,module,summary) VALUES(?,?,?)", (db.now_s(), "recon", json.dumps({"bad": bad_n})))
        g.db.commit()
        return jsonify(ok=True, source=f"Imported CSV, batch {latest}", **res)

    @app.post("/api/payment/verify")
    @login_required
    def api_payment_verify():
        b = body()
        return jsonify(ok=True, **reconciliation.verification_status(
            bool(b.get("official_app_credit_seen")), bool(b.get("amount_matches")), bool(b.get("txn_id_seen")), bool(b.get("only_screenshot"))))

    # ---------- Engine B: citizen safety ----------
    @app.get("/api/voice/guide")
    @login_required
    def api_voice_guide():
        return jsonify(ok=True, **voice_safety.guide())

    @app.post("/api/voice/check")
    @login_required
    def api_voice_check():
        res = voice_safety.evaluate(body().get("answers", {}))
        if res["level"] == "High":
            db.add_alert(g.db, "voice", "V01", "high", "Possible voice-clone / emergency scam call", "संभावित वॉइस-क्लोन / इमरजेंसी ठगी कॉल",
                         f"flags={','.join(res['flags'])}", "Citizen checklist (no call audio used)", res["en"], res["hi"])
            g.db.commit()
        return jsonify(ok=True, **res)

    @app.post("/api/apk/check")
    @login_required
    def api_apk_check():
        f = request.files.get("file")
        if not f:
            return bad("Choose a file.")
        res = apk_metadata.inspect(f.read(apk_metadata.MAX_BYTES + 1), f.filename or "app.apk")
        if res.get("ok") and res["level"] in ("High", "Medium"):
            db.add_alert(g.db, "apk", "A01", res["level"].lower(), f"Risky app file: {res['level']} risk indicators", f"जोखिम वाली ऐप फ़ाइल: {res['level']}",
                         f"sha256={res['sha256'][:16]} perms={','.join(res['permissions_found'][:6])}", "APK static review (not installed)",
                         res["note_en"], res["note_hi"])
            g.db.commit()
        return jsonify(**res), (200 if res.get("ok") else 400)

    # ---------- Engine C: Linux guard ----------
    @app.post("/api/scan/secrets")
    @login_required
    def api_scan_secrets():
        res = runners.run_secret_scan(g.db, body().get("path") or None)
        return (jsonify(**res), 200) if res["ok"] else (jsonify(ok=False, error=res["error"]), 400)

    @app.post("/api/fix/propose")
    @login_required
    def api_fix_propose():
        b = body()
        res = secret_scanner.propose_fix(b.get("root") or config.allowed_scan_roots()[0], str(b.get("file", "")), int(b.get("line", 0)), config.allowed_scan_roots())
        res.pop("new_lines", None)
        return jsonify(**res), (200 if res["ok"] else 400)

    @app.post("/api/fix/apply")
    @login_required
    def api_fix_apply():
        b = body()
        res = secret_scanner.apply_fix(b.get("root") or config.allowed_scan_roots()[0], str(b.get("file", "")), int(b.get("line", 0)),
                                       config.allowed_scan_roots(), approved=bool(b.get("approve")))
        if res["ok"]:
            db.audit(g.db, "fix_applied", f"{b.get('file')}:{b.get('line')} backup={res['backup']}")
            g.db.commit()
        return jsonify(**res), (200 if res["ok"] else 400)

    @app.post("/api/logins/run")
    @login_required
    def api_logins_run():
        return jsonify(ok=True, **runners.run_login_monitor(g.db, app.config["SAMPLE_LOG"]))

    @app.post("/api/logins/simulate")
    @login_required
    def api_logins_simulate():
        kind = body().get("kind", "brute")
        if kind not in ("brute", "spray", "success_after", "benign"):
            return bad("Unknown scenario.")
        with open(app.config["SAMPLE_LOG"], "a") as fh:      # synthetic lines, demo log only
            fh.write("\n".join(login_monitor.synth_lines(kind)) + "\n")
        return jsonify(ok=True, added=kind)

    # ---------- Engine D: factory simulator ----------
    @app.post("/api/iot/tick")
    @login_required
    def api_iot_tick():
        return jsonify(runners.iot_tick(g.db, body().get("mode", "normal")))

    @app.get("/api/iot/status")
    @login_required
    def api_iot_status():
        return jsonify(ok=True, **runners.iot_status(g.db))

    # ---------- alerts, readiness, export ----------
    @app.get("/api/alerts")
    @login_required
    def api_alerts():
        q, args = "SELECT * FROM alerts WHERE 1=1", []
        for col in ("module", "severity"):
            v = request.args.get(col)
            if v:
                q += f" AND {col}=?"
                args.append(v)
        if request.args.get("status") == "open":
            q += " AND ack=0"
        q += " ORDER BY id DESC LIMIT 200"
        return jsonify(ok=True, alerts=[dict(r) for r in g.db.execute(q, args)])

    @app.post("/api/alerts/<int:aid>/ack")
    @login_required
    def api_ack(aid):
        g.db.execute("UPDATE alerts SET ack=1 WHERE id=?", (aid,))
        g.db.commit()
        return jsonify(ok=True)

    def _last(module):
        r = g.db.execute("SELECT ts,summary FROM scans WHERE module=? ORDER BY id DESC LIMIT 1", (module,)).fetchone()
        return (db.parse_s(r["ts"]), json.loads(r["summary"])) if r else (None, None)

    @app.get("/api/readiness")
    @login_required
    def api_readiness():
        now = datetime.now()
        qr = g.db.execute("SELECT ts,status FROM qr_scans ORDER BY id DESC LIMIT 1").fetchone()
        ts, sec = _last("secret_scan")
        open_sec = g.db.execute("SELECT COUNT(*) c FROM alerts WHERE module='secret_scan' AND ack=0").fetchone()["c"]
        lts, lg = _last("login")
        open_login = g.db.execute("SELECT COUNT(*) c FROM alerts WHERE module='login' AND ack=0").fetchone()["c"]
        rts, rc = _last("recon")
        its = g.db.execute("SELECT ts FROM telemetry ORDER BY id DESC LIMIT 1").fetchone()
        iot_alerts = g.db.execute("SELECT COUNT(*) c FROM alerts WHERE module='factory' AND ack=0").fetchone()["c"]
        res = readiness.compute(
            now,
            {"status": qr["status"], "ts": db.parse_s(qr["ts"])} if qr else None,
            {"count": open_sec, "ts": ts} if ts else None,
            {"status": lg["status"], "count": open_login, "ts": lts} if lts else None,
            {"bad": rc["bad"], "ts": rts} if rts else None,
            {"alerts": iot_alerts, "ts": db.parse_s(its["ts"])} if its else None)
        res["open_high"] = g.db.execute("SELECT COUNT(*) c FROM alerts WHERE ack=0 AND severity='high'").fetchone()["c"]
        res["open_total"] = g.db.execute("SELECT COUNT(*) c FROM alerts WHERE ack=0").fetchone()["c"]
        return jsonify(ok=True, **res)

    @app.get("/api/export/alerts.csv")
    @login_required
    def api_export():
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["id", "time", "module", "rule", "severity", "title", "evidence", "source", "acknowledged"])
        for r in g.db.execute("SELECT * FROM alerts ORDER BY id"):
            row = [r["id"], r["ts"], r["module"], r["rule_id"], r["severity"], r["title_en"], r["evidence"], r["source"], r["ack"]]
            w.writerow([("'" + c) if isinstance(c, str) and c.startswith(CSV_DANGEROUS) else c for c in row])
        return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=scam_shield_alerts.csv"})

    # ---------- demo helpers (synthetic data only) ----------
    @app.post("/api/demo/load")
    @login_required
    def api_demo_load():
        now = datetime.now().replace(second=0, microsecond=0)
        g.db.execute("DELETE FROM sales")
        if not g.db.execute("SELECT 1 FROM registered_qrs").fetchone():
            g.db.execute("INSERT INTO registered_qrs(label,upi_id,payee_name,created) VALUES(?,?,?,?)",
                         ("Main counter", make_samples.SHOP_UPI, make_samples.SHOP_NAME, db.now_s()))
        for mins, amt in make_samples.DEMO_SALES:
            g.db.execute("INSERT INTO sales(ts,amount,ref,note) VALUES(?,?,?,?)",
                         ((now - timedelta(minutes=mins)).strftime("%Y-%m-%d %H:%M:%S"), amt, "", "demo"))
        rows, errors = reconciliation.parse_csv(make_samples.statement_csv(now))
        batch = db.now_s()
        g.db.executemany("INSERT INTO transactions(batch,txn_id,ts,amount,status,reference,duplicate) VALUES(?,?,?,?,?,?,?)",
                         [(batch, r["txn_id"], r["ts"].strftime("%Y-%m-%d %H:%M:%S"), r["amount"], r["status"], r["reference"], int(r["duplicate"])) for r in rows])
        db.audit(g.db, "demo_load", "synthetic sales + statement")
        g.db.commit()
        return jsonify(ok=True, sales=len(make_samples.DEMO_SALES), statement_rows=len(rows), rejected=errors)

    @app.post("/api/demo/reset")
    @login_required
    def api_demo_reset():
        for t in ("sales", "transactions", "alerts", "scans", "telemetry", "qr_scans"):
            g.db.execute(f"DELETE FROM {t}")
        open(app.config["SAMPLE_LOG"], "w").close()
        make_samples.main()
        db.audit(g.db, "demo_reset")
        g.db.commit()
        return jsonify(ok=True)

    return app


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    a = ap.parse_args()
    if a.host not in ("127.0.0.1", "localhost"):
        print("WARNING: exposing the dev server beyond this computer. Use only on a trusted network behind a firewall, never the internet.")
    create_app().run(host=a.host, port=a.port, debug=False)
