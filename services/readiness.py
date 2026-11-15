"""Transparent readiness indicator. No hidden percentage: every component shows its own state and freshness,
and a module that is off or stale shows 'Not assessed' instead of silently earning points."""
from datetime import timedelta

FRESH = timedelta(hours=24)
HEALTHY = {"Verified", "Clean", "Monitoring", "Reviewed"}
ACTION = {"Action needed", "Review needed", "Alert"}


def _age(ts, now):
    return None if not ts else now - ts


def compute(now, qr_last, secret_last, login_last, recon_last, iot_last):
    """qr_last{status,ts}, secret_last{count,ts}, login_last{status,count,ts}, recon_last{bad,ts}, iot_last{alerts,ts}; None = never run."""
    comps = []

    def add(name_en, name_hi, state, en, hi):
        comps.append({"name_en": name_en, "name_hi": name_hi, "state": state, "detail": en, "detail_hi": hi})

    QN, QH = "Registered QR check", "पंजीकृत QR जाँच"
    if not qr_last:
        add(QN, QH, "Not assessed", "No QR scanned yet", "अभी कोई QR स्कैन नहीं हुआ")
    elif _age(qr_last["ts"], now) > FRESH:
        add(QN, QH, "Stale", f"Last scan {qr_last['ts']:%d %b %H:%M}; rescan today", f"अंतिम स्कैन {qr_last['ts']:%d %b %H:%M}; आज फिर स्कैन करें")
    elif qr_last["status"] == "MATCH":
        add(QN, QH, "Verified", f"Matched at {qr_last['ts']:%H:%M}", f"{qr_last['ts']:%H:%M} पर मेल खाया")
    else:
        add(QN, QH, "Action needed", f"Latest scan: {qr_last['status']}", f"नवीनतम स्कैन: {qr_last['status']}")

    SN, SH = "Linux folder scan", "Linux फ़ोल्डर स्कैन"
    if not secret_last:
        add(SN, SH, "Not assessed", "No scan run yet", "अभी कोई स्कैन नहीं चला")
    elif _age(secret_last["ts"], now) > FRESH:
        add(SN, SH, "Stale", f"Last scan {secret_last['ts']:%d %b %H:%M}", f"अंतिम स्कैन {secret_last['ts']:%d %b %H:%M}")
    elif secret_last["count"] > 0:
        add(SN, SH, "Review needed", f"{secret_last['count']} open finding(s)", f"{secret_last['count']} खुले निष्कर्ष")
    else:
        add(SN, SH, "Clean", "No configured patterns found (not a guarantee)", "कोई तय पैटर्न नहीं मिला (गारंटी नहीं)")

    LN, LH = "Login monitoring", "लॉगिन निगरानी"
    demo = login_last and login_last["status"] == "DEMO_SAMPLE"
    d_en, d_hi = (" (demo log)", " (डेमो लॉग)") if demo else ("", "")
    if not login_last or login_last["status"] == "UNAVAILABLE":
        add(LN, LH, "Not assessed", "No readable log source", "कोई पढ़ने योग्य लॉग स्रोत नहीं")
    elif login_last["status"] == "PERMISSION_REQUIRED":
        add(LN, LH, "Not assessed", "Permission required for the real log", "असली लॉग के लिए अनुमति चाहिए")
    elif _age(login_last["ts"], now) > FRESH:
        add(LN, LH, "Stale", "Last run over 24 h ago", "अंतिम जाँच 24 घंटे से पुरानी")
    elif login_last["count"] > 0:
        add(LN, LH, "Review needed", f"{login_last['count']} pattern(s) flagged{d_en}", f"{login_last['count']} पैटर्न चिह्नित{d_hi}")
    else:
        add(LN, LH, "Monitoring", f"No threshold alert{d_en}", f"कोई सीमा अलर्ट नहीं{d_hi}")

    RN, RH = "Payment reconciliation", "भुगतान मिलान"
    if not recon_last:
        add(RN, RH, "Not assessed", "No statement imported", "कोई स्टेटमेंट आयात नहीं हुआ")
    elif _age(recon_last["ts"], now) > FRESH:
        add(RN, RH, "Stale", "Statement older than 24 h", "स्टेटमेंट 24 घंटे से पुराना")
    elif recon_last["bad"] > 0:
        add(RN, RH, "Review needed", f"{recon_last['bad']} sale(s) not matched", f"{recon_last['bad']} बिक्री का मिलान नहीं हुआ")
    else:
        add(RN, RH, "Reviewed", "All recorded sales found in the imported statement", "सभी दर्ज बिक्री आयात की स्टेटमेंट में मिलीं")

    IN, IH = "Factory monitor (simulated)", "फ़ैक्टरी निगरानी (सिम्युलेटेड)"
    if not iot_last:
        add(IN, IH, "Not assessed", "Simulator not started", "सिम्युलेटर शुरू नहीं हुआ")
    elif iot_last["alerts"] > 0:
        add(IN, IH, "Alert", f"{iot_last['alerts']} active rule(s)", f"{iot_last['alerts']} सक्रिय नियम")
    else:
        add(IN, IH, "Monitoring", "Within configured range", "तय सीमा के भीतर")

    healthy = sum(1 for c in comps if c["state"] in HEALTHY)
    if any(c["state"] in ACTION for c in comps):
        overall = "Action needed"
    elif any(c["state"] in ("Not assessed", "Stale") for c in comps):
        overall = "Incomplete"
    else:
        overall = "All configured checks healthy"
    return {"components": comps, "healthy": healthy, "total": len(comps), "overall": overall,
            "note": "Readiness indicator from configured checks only. It is not a claim that the business is secure."}
