import io
import os
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import config
from services import (apk_metadata, iot_sim, login_monitor, qr_integrity, readiness, reconciliation,
                      secret_scanner, voice_safety)

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data"
REG = [{"label": "main", "upi_id": "sharmageneral@okaxis", "payee_name": "Sharma General Store"}]


# ---------- QR ----------
@pytest.mark.parametrize("fname,expected", [
    ("01_genuine_shop_qr.png", "MATCH"), ("02_lookalike_swapped_qr.png", "MISMATCH"), ("03_different_payee_qr.png", "MISMATCH"),
    ("04_shortened_link_qr.png", "NOT_UPI"), ("05_name_differs_qr.png", "PARTIAL")])
def test_qr_images(fname, expected):
    payload = qr_integrity.decode_image((SAMPLE / "qr" / fname).read_bytes())
    assert qr_integrity.compare(payload, REG)["status"] == expected


def test_qr_lookalike_is_called_out():
    r = qr_integrity.compare("upi://pay?pa=sharmagenera1@okaxis&pn=Sharma", REG)
    assert r["status"] == "MISMATCH" and "look_alike_of_registered" in r["flags"]


def test_qr_unreadable_and_malformed():
    assert qr_integrity.decode_image(b"not an image") is None
    assert qr_integrity.compare(None, REG)["status"] == "UNABLE_TO_PARSE"
    assert qr_integrity.compare("upi://pay?pn=NoAddress", REG)["status"] == "UNABLE_TO_PARSE"
    assert qr_integrity.compare("upi://pay?pa=not-an-id", REG)["status"] == "UNABLE_TO_PARSE"


def test_qr_double_payee_is_rejected():
    r = qr_integrity.compare("upi://pay?pa=sharmageneral@okaxis&pa=thief@ybl", REG)
    assert r["status"] == "MISMATCH" and "duplicate_pa" in r["flags"]


def test_qr_match_wording_does_not_claim_payment():
    r = qr_integrity.compare("upi://pay?pa=SharmaGeneral@OkAxis&pn=Sharma%20General%20Store", REG)
    assert r["status"] == "MATCH" and "not that any payment arrived" in r["en"]


# ---------- reconciliation ----------
def _sales(now):
    return [{"id": 1, "ts": now - timedelta(minutes=60), "amount": 250.0, "ref": ""},
            {"id": 2, "ts": now - timedelta(minutes=30), "amount": 999.0, "ref": ""},
            {"id": 3, "ts": now - timedelta(minutes=20), "amount": 450.0, "ref": ""}]


def test_reconcile_states():
    now = datetime(2026, 11, 14, 12, 0)
    csv = ("txn_id,timestamp,amount,status\n"
           f"A1,{(now - timedelta(minutes=59)):%Y-%m-%d %H:%M:%S},250,SUCCESS\n"
           f"A1,{(now - timedelta(minutes=59)):%Y-%m-%d %H:%M:%S},250,SUCCESS\n"
           f"A2,{(now - timedelta(minutes=19)):%Y-%m-%d %H:%M:%S},450,PENDING\n"
           f"A3,{(now - timedelta(minutes=5)):%Y-%m-%d %H:%M:%S},-50,REFUND\nbroken\n")
    rows, errs = reconciliation.parse_csv(csv)
    assert len(errs) == 1 and any(r["duplicate"] for r in rows)
    res = reconciliation.reconcile(_sales(now), rows)
    st = {r["sale_id"]: r["status"] for r in res["rows"]}
    assert st == {1: "MATCHED", 2: "UNMATCHED", 3: "PENDING"}
    assert res["summary"]["duplicates"] == ["A1"] and res["summary"]["refunds"] == ["A3"]


def test_reconcile_ambiguous_is_not_guessed():
    now = datetime(2026, 11, 14, 12, 0)
    rows, _ = reconciliation.parse_csv("txn_id,timestamp,amount,status\n"
                                       f"X1,{now:%Y-%m-%d %H:%M:%S},100,SUCCESS\nX2,{now:%Y-%m-%d %H:%M:%S},100,SUCCESS\n")
    res = reconciliation.reconcile([{"id": 1, "ts": now, "amount": 100.0, "ref": ""}], rows)
    assert res["rows"][0]["status"] == "AMBIGUOUS" and set(res["rows"][0]["candidates"]) == {"X1", "X2"}


def test_reconcile_reference_match_wins():
    now = datetime(2026, 11, 14, 12, 0)
    rows, _ = reconciliation.parse_csv("txn_id,timestamp,amount,status,reference\n"
                                       f"X1,{now:%Y-%m-%d %H:%M:%S},100,SUCCESS,INV-7\nX2,{now:%Y-%m-%d %H:%M:%S},100,SUCCESS,INV-8\n")
    res = reconciliation.reconcile([{"id": 1, "ts": now, "amount": 100.0, "ref": "inv-7"}], rows)
    assert res["rows"][0]["status"] == "MATCHED" and res["rows"][0]["txn_id"] == "X1"


def test_csv_missing_columns_and_garbage():
    rows, errs = reconciliation.parse_csv("id,when,value\n1,2,3\n")
    assert rows == [] and "Missing required" in errs[0]["error"]
    rows, errs = reconciliation.parse_csv(b"\xff\xfe\x00garbage")
    assert rows == []


def test_unmatched_wording_does_not_claim_fraud_or_settlement():
    now = datetime(2026, 11, 14, 12, 0)
    res = reconciliation.reconcile([{"id": 1, "ts": now, "amount": 77.0, "ref": ""}], [])
    txt = res["rows"][0]["en"].lower()
    assert "no matching entry" in txt and "settled" not in txt and "fraud" not in txt


def test_screenshot_alone_is_never_verified():
    assert reconciliation.verification_status(only_screenshot=True)["status"] == "NOT_VERIFIED"
    assert reconciliation.verification_status(only_screenshot=True, txn_id_seen=True)["status"] == "NOT_VERIFIED"
    assert reconciliation.verification_status()["status"] == "NOT_VERIFIED"
    assert reconciliation.verification_status(txn_id_seen=True)["status"] == "NEEDS_CHECKING"
    assert reconciliation.verification_status(official_app_credit_seen=True, amount_matches=True)["status"].startswith("VERIFIED")


# ---------- secret scanner ----------
def test_scanner_finds_masks_and_ignores_placeholders():
    res = secret_scanner.scan(SAMPLE / "scan_target", config.allowed_scan_roots())
    assert res["ok"]
    found = {(f["file"], f["rule_id"]) for f in res["findings"]}
    assert ("billing_app.py", "S006") in found and ("deploy.env", "S001") in found and ("deploy.env", "S007") in found
    blob = repr(res["findings"])
    for secret in ("Rj9#kL2mQ8vXz4Tn", "d93Kx0LpQm72VnB8sWe5", "AKIAQ7XK2MZP4WNB5TDE", "pX7mK2vL9qZ"):
        assert secret not in blob, "a raw secret leaked into the findings"
    assert not any(f["file"] == "notes.txt" for f in res["findings"])             # '<your-token-here>' placeholder
    assert not any(f["line"] == 4 and f["file"] == "billing_app.py" for f in res["findings"])  # os.environ.get(...)


def test_scanner_blocks_path_traversal_and_outside_roots(tmp_path):
    roots = config.allowed_scan_roots()
    assert not secret_scanner.scan("/etc", roots)["ok"]
    assert not secret_scanner.scan(SAMPLE / "scan_target" / ".." / "..", roots)["ok"]
    assert not secret_scanner.scan(tmp_path / "nope", roots)["ok"]
    link = tmp_path / "link"
    try:
        os.symlink("/etc", link)
        assert not secret_scanner.scan(link, roots)["ok"]
    except OSError:
        pass


def test_scanner_skips_binary_and_huge_files(tmp_path):
    (tmp_path / "bin.txt").write_bytes(b"\x00\x01AKIAQ7XK2MZP4WNB5TDE\x00")
    (tmp_path / "big.txt").write_text("x" * (secret_scanner.MAX_FILE_BYTES + 10) + "\nAKIAQ7XK2MZP4WNB5TDE")
    res = secret_scanner.scan(tmp_path, [tmp_path])
    assert res["ok"] and res["findings"] == [] and res["files_skipped"] == 2


def test_fix_requires_approval_backs_up_and_shows_diff(tmp_scan):
    roots = config.allowed_scan_roots()
    prop = secret_scanner.propose_fix(tmp_scan, "billing_app.py", 3, roots)
    assert prop["ok"] and "os.environ.get" in prop["diff"]
    assert "Rj9#kL2mQ8vXz4Tn" not in prop["diff"], "the proposed diff must not reveal the secret"
    before = (tmp_scan / "billing_app.py").read_text()
    assert not secret_scanner.apply_fix(tmp_scan, "billing_app.py", 3, roots, approved=False)["ok"]
    assert (tmp_scan / "billing_app.py").read_text() == before                  # nothing silently rewritten
    done = secret_scanner.apply_fix(tmp_scan, "billing_app.py", 3, roots, approved=True)
    assert done["ok"] and (tmp_scan / done["backup"]).read_text() == before
    after = (tmp_scan / "billing_app.py").read_text()
    assert "Rj9#kL2mQ8vXz4Tn" not in after and 'os.environ.get("DB_PASSWORD"' in after
    compile(after, "billing_app.py", "exec")                                    # still valid Python


def test_fix_rejects_non_assignment_and_traversal(tmp_scan):
    roots = config.allowed_scan_roots()
    assert not secret_scanner.propose_fix(tmp_scan, "billing_app.py", 11, roots)["ok"]
    assert not secret_scanner.propose_fix(tmp_scan, "../../../etc/passwd", 1, roots)["ok"]
    assert not secret_scanner.propose_fix(tmp_scan, "deploy.env", 1, roots)["ok"]


# ---------- login monitor ----------
def L(t, msg):
    return f"{t:%b %e %H:%M:%S} host sshd[1]: {msg}"


def test_brute_force_flagged_with_cautious_wording():
    t0 = datetime(2026, 11, 14, 10, 0, 0)
    lines = [L(t0 + timedelta(seconds=i * 5), f"Failed password for admin from 203.0.113.45 port {4000+i} ssh2") for i in range(6)]
    f = login_monitor.detect(login_monitor.parse_events(lines, 2026))
    assert len(f) == 1 and f[0]["rule_id"] == "L01" and f[0]["severity"] == "medium"
    assert "possible" in f[0]["en"] and f[0]["source"] == "203.0.113.x"          # IP masked


def test_single_failure_and_typo_are_not_alerts():
    t0 = datetime(2026, 11, 14, 10, 0, 0)
    lines = [L(t0, "Failed password for shopkeeper from 192.0.2.10 port 1 ssh2"), L(t0 + timedelta(seconds=9), "Accepted password for shopkeeper from 192.0.2.10 port 2 ssh2")]
    assert login_monitor.detect(login_monitor.parse_events(lines, 2026)) == []


def test_spread_out_failures_below_threshold_in_window():
    t0 = datetime(2026, 11, 14, 10, 0, 0)
    lines = [L(t0 + timedelta(minutes=i * 10), f"Failed password for admin from 203.0.113.45 port {i} ssh2") for i in range(6)]
    assert login_monitor.detect(login_monitor.parse_events(lines, 2026)) == []


def test_spray_and_success_after_failures():
    t0 = datetime(2026, 11, 14, 10, 0, 0)
    spray = [L(t0 + timedelta(seconds=i * 7), f"Failed password for invalid user {u} from 198.51.100.7 port {i} ssh2") for i, u in enumerate(["root", "admin", "pos", "test"])]
    assert login_monitor.detect(login_monitor.parse_events(spray, 2026))[0]["rule_id"] == "L02"
    ok = [L(t0 + timedelta(seconds=i * 5), f"Failed password for bob from 203.0.113.9 port {i} ssh2") for i in range(6)]
    ok.append(L(t0 + timedelta(seconds=60), "Accepted password for bob from 203.0.113.9 port 99 ssh2"))
    assert login_monitor.detect(login_monitor.parse_events(ok, 2026))[0]["rule_id"] == "L03"


def test_parser_ignores_garbage_and_supports_iso():
    ev = login_monitor.parse_events(["garbage", "", "Nov 99 99:99:99 h sshd[1]: Failed password for a from 1.2.3.4 port 1",
                                     "2026-11-14T10:00:00+05:30 h sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2"], 2026)
    assert len(ev) == 1 and ev[0]["ip"] == "1.2.3.4"


def test_log_source_honesty(tmp_path):
    missing = login_monitor.read_source(str(tmp_path / "none.log"), None)
    assert missing["status"] in ("UNAVAILABLE", "ACTIVE")                       # ACTIVE only if journald really exists
    demo = login_monitor.read_source(str(tmp_path / "none.log"), SAMPLE / "auth_sample.log")
    assert demo["status"] in ("DEMO_SAMPLE", "ACTIVE")
    if demo["status"] == "DEMO_SAMPLE":
        assert demo["demo"] is True


# ---------- IoT ----------
def _readings(temps, now):
    return [{"ts": now - timedelta(seconds=(len(temps) - i) * 3), "temp_c": t, "vibration_mm_s": 3.0, "current_a": 9.0} for i, t in enumerate(temps)]


def test_iot_rules():
    now = datetime.now()
    assert iot_sim.evaluate(_readings([60, 61, 59], now), now) == []                         # normal variation
    assert {a["rule_id"] for a in iot_sim.evaluate(_readings([60, 92], now), now)} >= {"I01", "I02"}
    assert "I03" in {a["rule_id"] for a in iot_sim.evaluate(_readings([90, 93, 96], now), now)}
    late = iot_sim.evaluate(_readings([60, 61], now), now + timedelta(seconds=90))
    assert [a["rule_id"] for a in late] == ["I04"]
    assert iot_sim.evaluate([], now) == []


def test_iot_alerts_state_the_safe_boundary_and_module_has_no_control_path():
    now = datetime.now()
    a = iot_sim.evaluate(_readings([95], now), now)[0]
    assert "no control commands" in a["action_en"].lower()
    src = Path(iot_sim.__file__).read_text()
    for banned in ("socket", "subprocess", "requests", "serial", "modbus", "os.system"):
        assert banned not in src, f"simulator imports/uses {banned}"


def test_iot_simulator_modes():
    import random
    r = random.Random(1)
    assert iot_sim.next_reading(None, "heartbeat_loss", r) is None
    t = None
    for _ in range(3):
        t = iot_sim.next_reading(t, "overheat", r)
    assert t["temp_c"] > 85
    assert iot_sim.next_reading(None, "vibration", r)["vibration_mm_s"] > 7


# ---------- APK ----------
def _apk(perms, extra=None):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        if perms is not None:
            z.writestr("AndroidManifest.xml", " ".join(f"android.permission.{p}" for p in perms))
        for k, v in (extra or {}).items():
            z.writestr(k, v)
    return b.getvalue()


def test_apk_review_flags_sms_stealer_pattern_without_executing():
    r = apk_metadata.inspect(_apk(["READ_SMS", "RECEIVE_SMS", "BIND_ACCESSIBILITY_SERVICE"]), "SBI_KYC_Update.apk")
    assert r["ok"] and r["level"] == "High" and "READ_SMS" in r["permissions_found"] and "not installed" in r["note_en"]


def test_apk_benign_and_invalid():
    assert apk_metadata.inspect(_apk(["INTERNET"]), "notes.apk")["level"] == "Low"
    assert not apk_metadata.inspect(b"plain text", "x.apk")["ok"]
    assert not apk_metadata.inspect(b"0" * (apk_metadata.MAX_BYTES + 1), "x.apk")["ok"]
    assert apk_metadata.inspect(_apk(None), "x.apk")["reasons"][0]["id"] == "A03"


# ---------- readiness & voice ----------
def test_readiness_is_transparent_and_never_a_percentage():
    now = datetime(2026, 11, 14, 12, 0)
    empty = readiness.compute(now, None, None, None, None, None)
    assert empty["overall"] == "Incomplete" and all(c["state"] == "Not assessed" for c in empty["components"]) and empty["healthy"] == 0
    good = readiness.compute(now, {"status": "MATCH", "ts": now}, {"count": 0, "ts": now}, {"status": "ACTIVE", "count": 0, "ts": now},
                             {"bad": 0, "ts": now}, {"alerts": 0, "ts": now})
    assert good["overall"] == "All configured checks healthy" and good["healthy"] == 5
    bad = readiness.compute(now, {"status": "MISMATCH", "ts": now}, {"count": 2, "ts": now}, None, None, None)
    assert bad["overall"] == "Action needed"
    stale = readiness.compute(now, {"status": "MATCH", "ts": now - timedelta(days=2)}, None, None, None, None)
    assert stale["components"][0]["state"] == "Stale"
    assert "%" not in str(good)


def test_voice_guidance_is_callback_based_and_privacy_safe():
    g = voice_safety.guide()
    assert any("saved in your phone" in s["en"] for s in g["steps"]) and "never records" in g["consent_en"].lower()
    assert voice_safety.evaluate({})["level"] == "Low"
    assert voice_safety.evaluate({"urgent_money": True})["level"] == "Medium"
    assert voice_safety.evaluate({"urgent_money": True, "secrecy": True})["level"] == "High"
