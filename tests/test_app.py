"""End-to-end tests through the real Flask app: auth, CSRF, upload limits, every API, and privacy rules."""
import io
import re
from pathlib import Path

import app as appmod

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data"


def post(c, path, **kw):
    h = {"X-CSRF-Token": c.csrf}
    return c.post(path, headers=h, **kw)


def j(c, path, payload=None):
    return post(c, path, json=payload or {}).get_json()


def test_auth_required_everywhere(tmp_path, tmp_scan):
    a = appmod.create_app(tmp_path / "i")
    c = a.test_client()
    assert c.get("/").status_code == 302 and "/login" in c.get("/").headers["Location"]
    assert "/setup" in c.get("/login").headers["Location"]                       # no user yet => forced first-run setup
    for p in ("/api/alerts", "/api/readiness", "/api/export/alerts.csv", "/api/sales", "/api/iot/status"):
        assert c.get(p).status_code in (401, 302)
    assert c.post("/api/analyze", json={"text": "x"}).status_code in (400, 401)


def test_setup_rules_and_login_throttle(tmp_path, tmp_scan):
    from tests.conftest import _tok
    a = appmod.create_app(tmp_path / "i")
    c = a.test_client()
    r = c.post("/setup", data={"username": "a b", "password": "12345678", "csrf_token": _tok(c, "/setup")})
    assert b"Username" in r.data
    r = c.post("/setup", data={"username": "owner", "password": "short", "csrf_token": _tok(c, "/setup")})
    assert b"at least 8" in r.data
    c.post("/setup", data={"username": "owner", "password": "longenough1", "csrf_token": _tok(c, "/setup")})
    assert c.get("/setup").status_code == 302                                      # setup closes after first user
    for _ in range(5):
        c.post("/login", data={"username": "owner", "password": "wrong", "csrf_token": _tok(c, "/login")})
    r = c.post("/login", data={"username": "owner", "password": "longenough1", "csrf_token": _tok(c, "/login")})
    assert b"Too many attempts" in r.data                                          # locked even for the right password
    with app_ctx(a) as conn:
        assert conn.execute("SELECT pw_hash FROM users").fetchone()[0].startswith(("scrypt:", "pbkdf2:"))  # hashed, never plain


class app_ctx:
    def __init__(self, a): self.a = a
    def __enter__(self):
        import db
        self.c = db.connect(self.a.config["DB_PATH"]); return self.c
    def __exit__(self, *x): self.c.close()


def test_csrf_is_enforced(client):
    assert client.post("/api/analyze", json={"text": "hello world"}).status_code == 400
    assert client.post("/api/analyze", json={"text": "hello world"}, headers={"X-CSRF-Token": "bad"}).status_code == 400
    assert j(client, "/api/analyze", {"text": "hello world"})["ok"]


def test_security_headers_and_no_store(client):
    r = client.get("/api/readiness")
    assert "script-src 'self'" in r.headers["Content-Security-Policy"] and r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    page = client.get("/").get_data(as_text=True)
    assert "onclick=" not in page and "<script>" not in page                       # no inline script, CSP-safe


def test_analyze_creates_alert_but_does_not_store_text(client):
    secret_text = "Refund pending. Enter your UPI PIN to receive money. Call 98765-43210 now"
    r = j(client, "/api/analyze", {"text": secret_text})
    assert r["level"] == "High"
    alerts = client.get("/api/alerts").get_json()["alerts"]
    assert alerts and alerts[0]["module"] == "message"
    assert "98765" not in str(alerts) and "UPI PIN" not in alerts[0]["evidence"]   # only rule ids + length stored
    assert not j(client, "/api/analyze", {"text": "x" * 6000})["ok"]
    low = j(client, "/api/analyze", {"text": "Your bill is due on the 20th"})
    assert low["level"] == "Low" and len(client.get("/api/alerts").get_json()["alerts"]) == 1   # Low raises no alert


def test_qr_flow_uploads_and_validation(client):
    assert not j(client, "/api/qr/scan", {"payload": "upi://pay?pa=a@b"})["ok"]                 # must register first
    assert not j(client, "/api/qr/registered", {"upi_id": "bad id", "payee_name": "x"})["ok"]
    assert j(client, "/api/qr/registered", {"label": "Main", "upi_id": "sharmageneral@okaxis", "payee_name": "Sharma General Store"})["ok"]

    def scan(name):
        data = (SAMPLE / "qr" / name).read_bytes()
        return post(client, "/api/qr/scan", data={"image": (io.BytesIO(data), name)}, content_type="multipart/form-data").get_json()
    assert scan("01_genuine_shop_qr.png")["status"] == "MATCH"
    r = scan("02_lookalike_swapped_qr.png")
    assert r["status"] == "MISMATCH" and "SIMILAR" in r["en"].upper()
    assert any(a["module"] == "qr" for a in client.get("/api/alerts").get_json()["alerts"])
    bad = post(client, "/api/qr/scan", data={"image": (io.BytesIO(b"MZ\x90 not an image"), "evil.exe")}, content_type="multipart/form-data")
    assert bad.status_code == 400
    big = post(client, "/api/qr/scan", data={"image": (io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"0" * 2_100_000), "big.png")}, content_type="multipart/form-data")
    assert big.status_code == 400
    assert len(client.get("/api/qr/history").get_json()["history"]) >= 2


def test_demo_reconciliation_end_to_end(client):
    assert not client.get("/api/recon/run").get_json()["ok"]                                      # nothing imported yet
    assert j(client, "/api/demo/load")["ok"]
    r = client.get("/api/recon/run").get_json()
    st = [x["status"] for x in r["rows"]]
    assert st.count("MATCHED") == 3 and st.count("UNMATCHED") == 1 and st.count("PENDING") == 1
    assert r["summary"]["duplicates"] == ["T1003"] and r["summary"]["refunds"] == ["T1005"]
    assert "Imported CSV" in r["source"]
    alerts = client.get("/api/alerts?module=payments").get_json()["alerts"]
    assert len(alerts) == 1 and "missing payment" in alerts[0]["title_en"].lower() and alerts[0]["severity"] == "high"
    client.get("/api/recon/run")                                                                  # re-run must not duplicate alerts
    assert len(client.get("/api/alerts?module=payments&status=open").get_json()["alerts"]) == 1


def test_csv_import_validation(client):
    def up(name, content):
        return post(client, "/api/recon/import", data={"file": (io.BytesIO(content), name)}, content_type="multipart/form-data")
    assert up("a.txt", b"x").status_code == 400
    r = up("a.csv", (SAMPLE / "statement_bad_columns.csv").read_bytes())
    assert r.status_code == 400 and "Missing required" in r.get_json()["errors"][0]["error"]
    ok = up("good.csv", (SAMPLE / "statement_good.csv").read_bytes()).get_json()
    assert ok["ok"] and ok["duplicates"] == 1 and len(ok["rejected"]) == 1
    assert up("huge.csv", b"txn_id,timestamp,amount,status\n" + b"a" * 1_100_000).status_code == 400


def test_sales_validation(client):
    assert not j(client, "/api/sales", {"amount": "abc"})["ok"]
    assert not j(client, "/api/sales", {"amount": "-5"})["ok"]
    assert j(client, "/api/sales", {"amount": "250", "ref": "INV-1"})["ok"]


def test_payment_verification_endpoint(client):
    assert j(client, "/api/payment/verify", {"only_screenshot": True})["status"] == "NOT_VERIFIED"
    assert j(client, "/api/payment/verify", {"official_app_credit_seen": True, "amount_matches": True})["status"].startswith("VERIFIED")


def test_secret_scan_alerts_are_masked_and_fix_flow(client, tmp_scan):
    r = j(client, "/api/scan/secrets")
    assert r["ok"] and r["findings"]
    alerts = client.get("/api/alerts?module=secret_scan").get_json()["alerts"]
    assert alerts and "Rj9#kL2mQ8vXz4Tn" not in str(alerts) and "AKIAQ7XK2MZP4WNB5TDE" not in str(alerts)
    n = len(alerts)
    j(client, "/api/scan/secrets")
    assert len(client.get("/api/alerts?module=secret_scan&status=open").get_json()["alerts"]) == n   # re-scan supersedes, no pile-up
    assert not j(client, "/api/scan/secrets", {"path": "/etc"})["ok"]
    assert not j(client, "/api/scan/secrets", {"path": "../../.."})["ok"]
    root = str(tmp_scan)
    prop = j(client, "/api/fix/propose", {"root": root, "file": "billing_app.py", "line": 3})
    assert prop["ok"] and "os.environ.get" in prop["diff"]
    assert not j(client, "/api/fix/apply", {"root": root, "file": "billing_app.py", "line": 3})["ok"]      # no approval => refused
    done = j(client, "/api/fix/apply", {"root": root, "file": "billing_app.py", "line": 3, "approve": True})
    assert done["ok"] and (tmp_scan / done["backup"]).exists()
    assert not j(client, "/api/fix/propose", {"root": "/etc", "file": "passwd", "line": 1})["ok"]


def test_login_monitor_states_demo_source_and_scenarios(client):
    r = j(client, "/api/logins/run")
    assert r["ok"] and r["status"] in ("DEMO_SAMPLE", "ACTIVE", "PERMISSION_REQUIRED")
    if r["demo"]:
        assert any(a["module"] == "login" and "demo log" in a["source"] for a in client.get("/api/alerts?module=login").get_json()["alerts"])
    assert j(client, "/api/logins/simulate", {"kind": "spray"})["ok"]
    assert not j(client, "/api/logins/simulate", {"kind": "rm -rf"})["ok"]


def test_iot_flow_overheat_then_silence(client):
    assert client.get("/api/iot/status").get_json()["assessed"] is False
    for _ in range(2):
        j(client, "/api/iot/tick", {"mode": "normal"})
    assert not [a for a in j(client, "/api/iot/tick", {"mode": "normal"})["alerts"] if a["severity"] == "high"]
    for _ in range(4):
        r = j(client, "/api/iot/tick", {"mode": "overheat"})
    assert any(a["rule_id"] == "I01" and a["severity"] == "high" for a in r["alerts"]) and r["simulated"] is True
    assert "no control commands" in r["boundary"].lower()
    s = j(client, "/api/iot/tick", {"mode": "heartbeat_loss"})
    assert any(a["rule_id"] == "I04" for a in s["alerts"])
    assert not j(client, "/api/iot/tick", {"mode": "shutdown_machine"})["ok"]
    assert any(a["module"] == "factory" and "SIMULATED" in a["source"] for a in client.get("/api/alerts?module=factory").get_json()["alerts"])


def test_apk_and_voice_endpoints(client):
    import zipfile
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("AndroidManifest.xml", "android.permission.READ_SMS android.permission.RECEIVE_SMS android.permission.BIND_ACCESSIBILITY_SERVICE")
    r = post(client, "/api/apk/check", data={"file": (io.BytesIO(b.getvalue()), "SBI_KYC.apk")}, content_type="multipart/form-data").get_json()
    assert r["ok"] and r["level"] == "High"
    assert post(client, "/api/apk/check", data={"file": (io.BytesIO(b"hello"), "x.apk")}, content_type="multipart/form-data").status_code == 400
    assert client.get("/api/voice/guide").get_json()["steps"]
    assert j(client, "/api/voice/check", {"answers": {"urgent_money": True, "no_video": True}})["level"] == "High"


def test_readiness_progression_and_honest_incomplete(client):
    r = client.get("/api/readiness").get_json()
    assert r["overall"] == "Incomplete" and r["healthy"] == 0 and r["total"] == 5
    j(client, "/api/qr/registered", {"upi_id": "sharmageneral@okaxis", "payee_name": "Sharma General Store"})
    j(client, "/api/qr/scan", {"payload": "upi://pay?pa=sharmageneral@okaxis&pn=Sharma%20General%20Store"})
    r = client.get("/api/readiness").get_json()
    assert next(c for c in r["components"] if "QR" in c["name_en"])["state"] == "Verified"
    j(client, "/api/qr/scan", {"payload": "upi://pay?pa=thief@ybl"})
    r = client.get("/api/readiness").get_json()
    assert r["overall"] == "Action needed"


def test_alert_ack_filter_and_csv_export_is_injection_safe(client):
    j(client, "/api/analyze", {"text": "Enter UPI PIN to receive refund immediately"})
    a = client.get("/api/alerts?status=open&severity=high").get_json()["alerts"]
    assert a
    assert j(client, f"/api/alerts/{a[0]['id']}/ack")["ok"]
    assert not client.get("/api/alerts?status=open&severity=high").get_json()["alerts"]
    from services import upi_risk
    import db
    with app_ctx(client.application) as conn:
        db.add_alert(conn, "message", "X", "low", "=HYPERLINK(\"http://evil\")", "x", "@cmd|' /C calc'!A0", "t")
        conn.commit()
    csv_text = client.get("/api/export/alerts.csv").get_data(as_text=True)
    assert "'=HYPERLINK" in csv_text and "'@cmd" in csv_text
    assert client.get("/api/export/alerts.csv").headers["Content-Disposition"].startswith("attachment")


def test_reset_and_logout(client):
    j(client, "/api/demo/load")
    assert j(client, "/api/demo/reset")["ok"]
    assert client.get("/api/alerts").get_json()["alerts"] == []
    assert client.post("/logout", data={"csrf_token": client.csrf}).status_code == 302
    assert client.get("/api/alerts").status_code == 401


def test_worker_single_pass(tmp_path, tmp_scan, capsys):
    import worker
    worker.one_pass(tmp_path / "w")
    out = capsys.readouterr().out
    assert "secret scan:" in out and "login monitor:" in out
    import db
    conn = db.connect(tmp_path / "w" / "shield.db")
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] > 0
    conn.close()
