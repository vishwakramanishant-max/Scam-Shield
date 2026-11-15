"""Operations shared by the web app and the background worker (so 'automatic' monitoring uses the same code)."""
import json
from datetime import datetime

import config
import db
from services import secret_scanner, login_monitor, iot_sim


def run_secret_scan(conn, path=None):
    roots = config.allowed_scan_roots()
    res = secret_scanner.scan(path or roots[0], roots)
    if not res["ok"]:
        return res
    # a fresh scan supersedes older open secret-scan alerts so counts stay honest
    conn.execute("UPDATE alerts SET ack=1 WHERE module='secret_scan' AND ack=0")
    for f in res["findings"]:
        if f["severity"] == "low":
            continue
        db.add_alert(conn, "secret_scan", f["rule_id"], f["severity"],
                     f"{f['type']} in {f['file']}:{f['line']}", f"{f['file']}:{f['line']} में {f['type_hi']}",
                     f"{f['file']}:{f['line']} value={f['masked']}", "Linux folder scan", f["advice"], f["advice_hi"])
    summary = {"findings": len(res["findings"]), "open": sum(1 for f in res["findings"] if f["severity"] != "low"),
               "files": res["files_scanned"], "root": res["root"]}
    conn.execute("INSERT INTO scans(ts,module,summary) VALUES(?,?,?)", (db.now_s(), "secret_scan", json.dumps(summary)))
    db.audit(conn, "secret_scan", f"{summary['files']} files, {summary['findings']} findings")
    conn.commit()
    return res


def run_login_monitor(conn, sample_log):
    src = login_monitor.read_source(config.REAL_AUTH_LOG, sample_log)
    events = login_monitor.parse_events(src["lines"])
    findings = login_monitor.detect(events)
    demo = " (demo log)" if src["demo"] else ""
    for f in findings:
        db.add_alert(conn, "login", f["rule_id"], f["severity"], f["en"], f["hi"],
                     f"source={f['source']} accounts={','.join(f['accounts'])} count={f['count']} {f['first']}..{f['last']}",
                     f"Auth log: {src['source']}{demo}", f["action_en"], f["action_hi"])
    summary = {"status": src["status"], "source": src["source"], "events": len(events), "findings": len(findings)}
    conn.execute("INSERT INTO scans(ts,module,summary) VALUES(?,?,?)", (db.now_s(), "login", json.dumps(summary)))
    conn.commit()
    return {"status": src["status"], "source": src["source"], "demo": src["demo"], "hint": src.get("hint"),
            "events_parsed": len(events), "findings": findings}


def iot_tick(conn, mode, rng=None):
    if mode not in iot_sim.MODES:
        return {"ok": False, "error": "Unknown simulator mode."}
    last = conn.execute("SELECT * FROM telemetry ORDER BY id DESC LIMIT 1").fetchone()
    prev = dict(last) if last else None
    reading = iot_sim.next_reading(prev, mode, rng)
    if reading:
        conn.execute("INSERT INTO telemetry(ts,temp_c,vibration_mm_s,current_a) VALUES(?,?,?,?)",
                     (reading["ts"].strftime("%Y-%m-%d %H:%M:%S"), reading["temp_c"], reading["vibration_mm_s"], reading["current_a"]))
    conn.commit()
    return {"ok": True, **iot_status(conn, force_heartbeat_check=(mode == "heartbeat_loss"))}


def iot_status(conn, force_heartbeat_check=False):
    rows = conn.execute("SELECT * FROM telemetry ORDER BY id DESC LIMIT 30").fetchall()
    readings = [{"ts": db.parse_s(r["ts"]), "temp_c": r["temp_c"], "vibration_mm_s": r["vibration_mm_s"], "current_a": r["current_a"]}
                for r in reversed(rows)]
    if not readings:
        return {"device": iot_sim.DEVICE, "simulated": True, "readings": [], "alerts": [], "boundary": iot_sim.SAFE_BOUNDARY, "assessed": False}
    now = datetime.now()
    if force_heartbeat_check:                      # the demo 'silence' button: age the last reading past the timeout
        from datetime import timedelta
        now = readings[-1]["ts"] + timedelta(seconds=iot_sim.HEARTBEAT_TIMEOUT_S + 5)
    alerts = iot_sim.evaluate(readings, now)
    for a in alerts:
        db.add_alert(conn, "factory", a["rule_id"], a["severity"], a["en"], a["hi"], a["evidence"] + " " + readings[-1]["ts"].strftime("%H:%M:%S"),
                     "Factory simulator (SIMULATED data)", a["action_en"], a["action_hi"])
    conn.commit()
    return {"device": iot_sim.DEVICE, "simulated": True, "assessed": True, "boundary": iot_sim.SAFE_BOUNDARY,
            "last_seen": readings[-1]["ts"].strftime("%H:%M:%S"), "alerts": alerts,
            "readings": [{"t": r["ts"].strftime("%H:%M:%S"), "temp": r["temp_c"], "vib": r["vibration_mm_s"], "cur": r["current_a"]} for r in readings]}
