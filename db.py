import sqlite3
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT);
CREATE TABLE IF NOT EXISTS registered_qrs(id INTEGER PRIMARY KEY, label TEXT, upi_id TEXT, payee_name TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS qr_scans(id INTEGER PRIMARY KEY, ts TEXT, status TEXT, observed TEXT, flags TEXT);
CREATE TABLE IF NOT EXISTS sales(id INTEGER PRIMARY KEY, ts TEXT, amount REAL, ref TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY, batch TEXT, txn_id TEXT, ts TEXT, amount REAL,
  status TEXT, reference TEXT, duplicate INTEGER);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts TEXT, module TEXT, rule_id TEXT, severity TEXT,
  title_en TEXT, title_hi TEXT, evidence TEXT, source TEXT, action_en TEXT, action_hi TEXT, ack INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, ts TEXT, module TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS telemetry(id INTEGER PRIMARY KEY, ts TEXT, temp_c REAL, vibration_mm_s REAL, current_a REAL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, action TEXT, detail TEXT);
"""


def now_s():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_s(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def connect(path):
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init(path):
    conn = connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def audit(conn, action, detail=""):
    conn.execute("INSERT INTO audit(ts,action,detail) VALUES(?,?,?)", (now_s(), action, detail[:300]))


def add_alert(conn, module, rule_id, severity, title_en, title_hi, evidence, source, action_en="", action_hi=""):
    """Insert an alert unless an identical un-acknowledged one already exists. Returns id or None."""
    dup = conn.execute("SELECT id FROM alerts WHERE module=? AND rule_id=? AND evidence=? AND ack=0",
                       (module, rule_id, evidence)).fetchone()
    if dup:
        return None
    cur = conn.execute(
        "INSERT INTO alerts(ts,module,rule_id,severity,title_en,title_hi,evidence,source,action_en,action_hi) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (now_s(), module, rule_id, severity, title_en, title_hi, evidence[:400], source, action_en, action_hi))
    return cur.lastrowid
