"""URL risk indicators. Pure functions: nothing here opens, resolves or fetches a URL."""
import re
from urllib.parse import urlparse

RULESET_VERSION = "url-1.0"

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd", "tiny.cc",
              "shorturl.at", "ow.ly", "rebrand.ly", "buff.ly"}
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "icu", "buzz", "monster", "cyou"}
SLD_SECOND_LEVEL = {"co.in", "org.in", "gov.in", "ac.in", "net.in", "com.au", "co.uk", "org.uk", "co.nz"}
KEYWORDS = ("kyc", "verify", "update", "secure", "login", "signin", "refund", "reward", "claim",
            "bonus", "lucky", "prize", "otp", "pin", "blocked", "suspend")

# brand token -> registrable domains that are genuinely theirs
BRANDS = {
    "paytm": {"paytm.com", "paytm.in"},
    "phonepe": {"phonepe.com"},
    "googlepay": {"google.com", "pay.google.com"},
    "gpay": {"google.com", "pay.google.com"},
    "bhim": {"bhimupi.org.in", "npci.org.in"},
    "npci": {"npci.org.in"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icici": {"icicibank.com", "icicilombard.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "kotak": {"kotak.com", "kotakbank.com"},
    "amazon": {"amazon.in", "amazon.com"},
    "flipkart": {"flipkart.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"})

URL_RE = re.compile(
    r"(?i)(?:https?://|www\.)[^\s<>\"']+"
    r"|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|rb\.gy|is\.gd|tiny\.cc|shorturl\.at|ow\.ly)/[^\s<>\"']+")
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def extract_urls(text):
    urls = []
    for m in URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;:!?)]}>'\"")
        if u and u not in urls:
            urls.append(u)
    return urls[:10]


def _edit_distance(a, b):
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registrable(host):
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SLD_SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _R(rid, w, en, hi):
    return {"id": rid, "weight": w, "en": en, "hi": hi}


def analyze(url):
    """Return {level, score, reasons, host}. level in Low/Medium/High/Unknown."""
    raw = (url or "").strip()
    if not raw or len(raw) > 2048:
        return {"level": "Unknown", "score": 0, "reasons": [], "host": None, "url": raw[:80]}
    candidate = raw if "://" in raw else "http://" + raw
    try:
        p = urlparse(candidate)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return {"level": "Unknown", "score": 0, "reasons": [], "host": None, "url": raw[:80]}
    if not host or " " in host or "." not in host and not IP_RE.match(host):
        return {"level": "Unknown", "score": 0, "reasons": [], "host": host or None, "url": raw[:80]}

    reasons = []
    reg = registrable(host)
    labels = host.split(".")
    official = any(reg in doms for doms in BRANDS.values())

    if raw.lower().startswith("http://"):
        reasons.append(_R("L01", 15, "Link is not encrypted (http, not https).", "लिंक एन्क्रिप्टेड नहीं है (http)।"))
    if IP_RE.match(host):
        reasons.append(_R("L02", 40, "Link uses a raw IP address instead of a website name.", "लिंक में वेबसाइट नाम की जगह सीधा IP पता है।"))
    if "xn--" in host or any(ord(c) > 127 for c in host):
        reasons.append(_R("L03", 40, "Domain uses look-alike (international) characters.", "डोमेन में मिलते-जुलते (अंतरराष्ट्रीय) अक्षर हैं।"))
    if reg in SHORTENERS:
        reasons.append(_R("L04", 30, "Shortened link hides the real destination (we did not open it).", "छोटा लिंक असली मंज़िल छिपाता है (हमने इसे खोला नहीं)।"))
    if p.username is not None or "@" in (p.netloc or ""):
        reasons.append(_R("L05", 40, "Link contains '@', a trick that disguises the real site.", "लिंक में '@' है, जो असली साइट छिपाने की चाल है।"))

    brand_hit = None
    if not official and not IP_RE.match(host):
        tokens = [t for part in labels for t in part.replace("_", "-").split("-") if t]
        for tok in tokens:
            base = tok.translate(LEET)
            # visual look-alikes: 'rn' reads as 'm', 'vv' as 'w'
            for norm in {base, base.replace("rn", "m"), base.replace("vv", "w")}:
                for brand in BRANDS:
                    if norm == brand or (len(brand) >= 5 and brand in norm) or \
                            (len(brand) >= 5 and len(norm) >= 5 and _edit_distance(norm, brand) <= 1 and norm != brand):
                        brand_hit = brand
                        break
                if brand_hit:
                    break
            if brand_hit:
                break
    if brand_hit:
        reasons.append(_R("L06", 50, f"Name imitates '{brand_hit}' but the site is not its official domain.",
                          f"नाम '{brand_hit}' जैसा दिखता है पर यह उसका आधिकारिक डोमेन नहीं है।"))

    if not official:
        hostpath = host + (p.path or "").lower()
        hit = [k for k in KEYWORDS if k in hostpath]
        if hit:
            reasons.append(_R("L07", 15, f"Pressure words in the link: {', '.join(hit[:3])}.", f"लिंक में दबाव वाले शब्द: {', '.join(hit[:3])}।"))
    tld = labels[-1]
    if tld in SUSPICIOUS_TLDS and not official:
        reasons.append(_R("L08", 20, f"Uncommon ending '.{tld}' is often used in throw-away scam sites.", f"'.{tld}' अंत अक्सर अस्थायी धोखाधड़ी साइटों में होता है।"))
    if len(labels) - len(reg.split(".")) >= 3 or len(host) > 45 or host.count("-") >= 3:
        reasons.append(_R("L09", 10, "Unusually long or complicated domain name.", "डोमेन नाम असामान्य रूप से लंबा या जटिल है।"))
    if port not in (None, 80, 443):
        reasons.append(_R("L10", 10, "Link uses an unusual network port.", "लिंक असामान्य पोर्ट इस्तेमाल करता है।"))

    score = min(100, sum(r["weight"] for r in reasons))
    level = "High" if score >= 50 else "Medium" if score >= 20 else "Low"
    if official and not reasons:
        reasons.append(_R("L00", 0, "Domain is on the built-in official list (not a guarantee).", "डोमेन अंतर्निहित आधिकारिक सूची में है (गारंटी नहीं)।"))
    return {"level": level, "score": score, "reasons": reasons, "host": host, "url": raw[:120]}
