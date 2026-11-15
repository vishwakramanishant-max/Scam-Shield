"""Reconcile recorded sales with an IMPORTED statement CSV. Never claims settlement: it only says what
the imported file does or does not contain."""
import csv
import io
from datetime import datetime, timedelta

REQUIRED = ["txn_id", "timestamp", "amount", "status"]
TS_FORMATS = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%d-%m-%Y %H:%M", "%d/%m/%Y %H:%M", "%d/%m/%Y %H:%M:%S"]
STATUS_MAP = {"SUCCESS": "success", "SUCCESSFUL": "success", "COMPLETED": "success", "CREDIT": "success",
              "PENDING": "pending", "PROCESSING": "pending", "INITIATED": "pending",
              "FAILED": "failed", "FAILURE": "failed", "DECLINED": "failed",
              "REFUND": "refund", "REVERSAL": "refund", "REVERSED": "refund"}
MAX_ROWS = 5000


def parse_ts(s):
    s = (s or "").strip()
    for f in TS_FORMATS:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(s.replace("Z", "")).replace(tzinfo=None)
    except ValueError:
        return None


def parse_amount(s):
    s = (s or "").replace("₹", "").replace("Rs.", "").replace("Rs", "").replace(",", "").strip()
    try:
        return round(float(s), 2)
    except ValueError:
        return None


def parse_csv(raw):
    """Returns (rows, errors). Rows are dicts with datetime ts; bad rows are rejected with the row number."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    headers = [h.strip().lower() for h in (reader.fieldnames or [])]
    missing = [h for h in REQUIRED if h not in headers]
    if missing:
        return [], [{"row": 0, "error": f"Missing required column(s): {', '.join(missing)}. Expected: txn_id,timestamp,amount,status[,reference]"}]
    rows, errors, seen = [], [], set()
    for i, r in enumerate(reader, start=2):
        if i - 1 > MAX_ROWS:
            errors.append({"row": i, "error": f"Row limit of {MAX_ROWS} reached; remaining rows ignored."})
            break
        r = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
        ts, amt = parse_ts(r.get("timestamp")), parse_amount(r.get("amount"))
        status_raw = r.get("status", "").upper()
        if not r.get("txn_id") or ts is None or amt is None or status_raw not in STATUS_MAP:
            errors.append({"row": i, "error": "Malformed row (txn_id, timestamp, amount or status invalid)."})
            continue
        status = STATUS_MAP[status_raw]
        if amt < 0:
            status, amt = "refund", abs(amt)
        dup = r["txn_id"] in seen
        seen.add(r["txn_id"])
        rows.append({"txn_id": r["txn_id"], "ts": ts, "amount": amt, "status": status,
                     "reference": r.get("reference", ""), "duplicate": dup})
    return rows, errors


STATUS_TEXT = {
    "MATCHED": ("Found in imported statement.", "आयात की गई स्टेटमेंट में मिला।"),
    "UNMATCHED": ("No matching entry in the imported statement. Check your official payment app and scan your QR now.",
                  "आयात की गई स्टेटमेंट में कोई मेल नहीं। अपना आधिकारिक पेमेंट ऐप जाँचें और अभी अपना QR स्कैन करें।"),
    "AMBIGUOUS": ("More than one statement entry fits this sale. Resolve it by hand using the reference.",
                  "इस बिक्री से एक से ज़्यादा एंट्री मेल खाती हैं। रेफ़रेंस से खुद तय करें।"),
    "PENDING": ("Statement shows this payment as pending, not completed.", "स्टेटमेंट में यह भुगतान लंबित दिख रहा है, पूरा नहीं।"),
    "FAILED": ("Statement shows a failed payment for this amount.", "स्टेटमेंट में इस राशि का भुगतान असफल दिख रहा है।"),
}


def reconcile(sales, txns, window_minutes=30):
    """sales: [{id, ts(datetime), amount, ref}]; txns: parse_csv rows. Greedy, chronological, honest about ambiguity."""
    window = timedelta(minutes=window_minutes)
    usable = [t for t in txns if not t["duplicate"]]
    consumed = set()
    out = []
    for s in sorted(sales, key=lambda x: x["ts"]):
        res = {"sale_id": s["id"], "amount": s["amount"], "ts": s["ts"].isoformat(sep=" ", timespec="minutes"),
               "status": None, "txn_id": None, "candidates": []}
        if s.get("ref"):
            for t in usable:
                if t["txn_id"] not in consumed and t["status"] == "success" and t["reference"].lower() == s["ref"].lower() \
                        and abs(t["amount"] - s["amount"]) < 0.005:
                    res.update(status="MATCHED", txn_id=t["txn_id"], via="reference")
                    consumed.add(t["txn_id"])
                    break
        if res["status"] is None:
            near = [t for t in usable if abs(t["amount"] - s["amount"]) < 0.005 and abs(t["ts"] - s["ts"]) <= window]
            ok = [t for t in near if t["status"] == "success" and t["txn_id"] not in consumed]
            if len(ok) == 1:
                res.update(status="MATCHED", txn_id=ok[0]["txn_id"], via="amount+time")
                consumed.add(ok[0]["txn_id"])
            elif len(ok) > 1:
                res.update(status="AMBIGUOUS", candidates=[t["txn_id"] for t in ok])
            elif any(t["status"] == "pending" for t in near):
                res["status"] = "PENDING"
            elif any(t["status"] == "failed" for t in near):
                res["status"] = "FAILED"
            else:
                res["status"] = "UNMATCHED"
        res["en"], res["hi"] = STATUS_TEXT[res["status"]]
        out.append(res)
    unmatched_txns = [t["txn_id"] for t in usable if t["status"] == "success" and t["txn_id"] not in consumed]
    summary = {k: sum(1 for r in out if r["status"] == k) for k in STATUS_TEXT}
    summary.update(duplicates=[t["txn_id"] for t in txns if t["duplicate"]],
                   refunds=[t["txn_id"] for t in txns if t["status"] == "refund"],
                   statement_entries_without_sale=unmatched_txns)
    return {"rows": out, "summary": summary}


def verification_status(official_app_credit_seen=False, amount_matches=False, txn_id_seen=False, only_screenshot=False):
    """Payment verification assistant. A screenshot alone can never become Verified."""
    if official_app_credit_seen and amount_matches:
        return {"status": "VERIFIED_BY_USER_IN_OFFICIAL_APP",
                "en": "Verified: you confirmed the credit inside your official payment app / bank channel.",
                "hi": "सत्यापित: आपने आधिकारिक पेमेंट ऐप / बैंक चैनल में क्रेडिट खुद देखा है।"}
    if only_screenshot or not (official_app_credit_seen or txn_id_seen):
        return {"status": "NOT_VERIFIED",
                "en": "Not verified. A screenshot is not proof of payment. Open your official app or bank SMS and look for the credit.",
                "hi": "सत्यापित नहीं। स्क्रीनशॉट भुगतान का सबूत नहीं है। अपना आधिकारिक ऐप या बैंक SMS खोलकर क्रेडिट देखें।"}
    return {"status": "NEEDS_CHECKING",
            "en": "Needs checking. Some details were seen, but the credit and amount are not both confirmed in your official app.",
            "hi": "जाँच ज़रूरी। कुछ जानकारी दिखी, पर क्रेडिट और राशि दोनों आधिकारिक ऐप में पुष्ट नहीं हैं।"}
