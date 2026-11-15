"""Explainable rule-based risk indicators for pasted payment/scam messages.
Output is a RISK INDICATOR, never a verdict and never a bank confirmation."""
import re
from . import url_risk

RULESET_VERSION = "msg-1.0"

NEGATION = re.compile(r"(do not|don't|dont|never|mat|न)\s+(\w+\s+){0,2}(share|tell|give|disclose|send|बताएं|बताना|शेयर)", re.I)
PIN_ASK = re.compile(r"\b(enter|share|send|give|tell|type|put|dalo|daalo|batao|bata do|bhejo)\b.{0,40}\b(upi\s*)?pin\b", re.I)
PIN_ASK_HI = re.compile(r"पिन.{0,20}(डालें|डालो|बताएं|बताओ|भेजें|दर्ज)|(डालें|बताएं|भेजें).{0,20}पिन")
RECEIVE = re.compile(r"\b(receive|refund|credit|cashback|get (the )?money|paisa|prize|reward|claim)\b|रिफंड|पैसे? (मिल|आ)", re.I)
OTP_ASK = re.compile(r"\b(enter|share|send|give|tell|read out|batao|bhejo)\b.{0,30}\b(otp|cvv|card number|card details|atm pin|net ?banking password)\b", re.I)
OTP_ASK_HI = re.compile(r"ओटीपी.{0,15}(बताएं|बताओ|भेजें|शेयर)|(बताएं|भेजें|शेयर).{0,15}ओटीपी")

RULES = [
    ("U04", 25, re.compile(r"\b(collect request|payment request|request money|approve (the |this )?(request|payment)|accept (the |this )?request)\b", re.I),
     "Approving a collect request SENDS money from your account; it never receives money.",
     "'कलेक्ट रिक्वेस्ट' मंज़ूर करने से आपके खाते से पैसे जाते हैं, आते नहीं।"),
    ("U05", 15, re.compile(r"\b(urgent(ly)?|immediately|right now|asap|within \d+ ?(min|minutes|hours?)|last chance|expires? (today|soon)|abhi|turant|jaldi)\b|तुरंत|जल्दी", re.I),
     "Creates urgency to stop you thinking.", "जल्दबाज़ी का दबाव बनाकर सोचने का समय नहीं देता।"),
    ("U06", 25, re.compile(r"\b(lottery|lucky draw|prize|you have won|you won|kbc|cashback offer|reward points|free gift|refund (is )?(pending|waiting|initiated))\b", re.I),
     "Prize / refund bait is a classic scam opening.", "इनाम / रिफंड का लालच ठगी की आम शुरुआत है।"),
    ("U07", 50, re.compile(r"\b(anydesk|teamviewer|quicksupport|rustdesk|screen ?share|remote access)\b", re.I),
     "Asks for a remote-access app, which lets a stranger control your phone.", "रिमोट-एक्सेस ऐप माँगता है, जिससे अजनबी आपका फ़ोन चला सकता है।"),
    ("U08", 40, re.compile(r"\.apk\b|install (this|the) (app|apk)|download (this|the) (app|apk)", re.I),
     "Asks you to install an app from outside the official store.", "आधिकारिक स्टोर के बाहर से ऐप इंस्टॉल करने को कहता है।"),
    ("U09", 30, re.compile(r"\b(kyc (is |will be )?(expired|expire|pending|update|suspended|blocked)|account (will be |has been |is )?(blocked|suspended|closed|frozen)|sim (will be )?blocked|bank (manager|officer|executive)|customer care executive|income tax (notice|department))\b", re.I),
     "Impersonates a bank/authority and threatens a block.", "बैंक/अधिकारी बनकर खाता बंद होने की धमकी देता है।"),
    ("U10", 30, re.compile(r"\b(this is my new number|new number)\b|\b(papa|mummy|beta|bhai|dad|mom)\b.{0,60}\b(accident|hospital|arrest|police|trouble|emergency)\b", re.I),
     "Family-emergency story from an unknown number; verify by calling the saved number.", "अनजान नंबर से परिवार की इमरजेंसी की कहानी; सेव किए नंबर पर कॉल करके जाँचें।"),
    ("U13", 20, re.compile(r"\b(send|transfer|pay|bhej(o|na)?)\b.{0,25}(\d{4,}|(₹|rs\.?|rupees|inr)\s?\d+)", re.I),
     "Asks you to send a specific amount of money.", "एक तय रकम भेजने को कहता है।"),
    ("U11", 25, re.compile(r"\b(processing fee|registration fee|advance (payment|fee)|security deposit|delivery charges?|customs fee)\b", re.I),
     "Asks for an upfront fee before giving money or goods.", "पैसे या सामान देने से पहले अग्रिम शुल्क माँगता है।"),
]
CRITICAL = {"U01", "U12"}


def _r(rid, w, en, hi, sev=None):
    return {"id": rid, "weight": w, "en": en, "hi": hi, "severity": sev or ("high" if w >= 45 else "medium" if w >= 20 else "low")}


def analyze(text):
    t = (text or "").strip()
    if len(t) < 4 or not re.search(r"[A-Za-zऀ-ॿ]", t):
        return {"level": "Unknown", "score": 0, "reasons": [], "urls": [], "ruleset": RULESET_VERSION,
                "next_en": "Could not analyse this input. Do not treat it as safe; verify manually.",
                "next_hi": "इस इनपुट का विश्लेषण नहीं हो सका। इसे सुरक्षित न मानें; खुद जाँचें।",
                "note_en": "Risk indicator only; not a guarantee.", "note_hi": "यह केवल जोखिम संकेत है; गारंटी नहीं।"}
    t = t[:5000]
    negated = bool(NEGATION.search(t))
    reasons = []
    pin = PIN_ASK.search(t) or PIN_ASK_HI.search(t)
    if pin and not negated:
        if RECEIVE.search(t):
            reasons.append(_r("U01", 70, "Asks for your UPI PIN in order to 'receive' money. The PIN is only ever needed to SEND money.",
                              "पैसे 'पाने' के लिए UPI पिन माँगता है। पिन सिर्फ़ पैसे भेजने के लिए लगता है।", "high"))
        else:
            reasons.append(_r("U02", 45, "Someone is asking you to enter or share a PIN.", "कोई आपसे पिन डालने या बताने को कह रहा है।", "high"))
    if (OTP_ASK.search(t) or OTP_ASK_HI.search(t)) and not negated:
        reasons.append(_r("U03", 45, "Asks for OTP / card details, which no genuine bank asks for.", "OTP / कार्ड विवरण माँगता है, जो असली बैंक कभी नहीं माँगता।", "high"))
    for rid, w, rx, en, hi in RULES:
        if rx.search(t):
            reasons.append(_r(rid, w, en, hi))
    urls = []
    for u in url_risk.extract_urls(t):
        res = url_risk.analyze(u)
        urls.append({"url": res["url"], "level": res["level"], "score": res["score"]})
        if res["level"] in ("High", "Medium"):
            w = 45 if res["level"] == "High" else 20
            ids = ",".join(r["id"] for r in res["reasons"])
            reasons.append(_r("U12", w, f"Suspicious link ({res['host']}): " + " ".join(r["en"] for r in res["reasons"][:2]),
                              f"संदिग्ध लिंक ({res['host']}): " + " ".join(r["hi"] for r in res["reasons"][:2]),
                              "high" if res["level"] == "High" else "medium"))
            reasons[-1]["url_rules"] = ids
    score = min(100, sum(r["weight"] for r in reasons))
    critical = any(r["id"] == "U01" for r in reasons)
    level = "High" if critical or score >= 60 else "Medium" if score >= 25 else "Low"
    nxt = {
        "High": ("Do not pay, click or share anything. End the conversation and verify through the official app or a number you already have saved.",
                 "पैसे न भेजें, लिंक न खोलें, कुछ साझा न करें। बातचीत बंद करें और आधिकारिक ऐप या अपने सेव किए नंबर से जाँचें।"),
        "Medium": ("Pause. Verify independently through the official app before acting.",
                   "रुकें। कुछ भी करने से पहले आधिकारिक ऐप से खुद जाँचें।"),
        "Low": ("No configured warning signs found. This is not a guarantee; still verify important payments in your official app.",
                "कोई तय चेतावनी संकेत नहीं मिला। यह गारंटी नहीं है; ज़रूरी भुगतान आधिकारिक ऐप में जाँचें।"),
    }[level]
    return {"level": level, "score": score, "reasons": reasons, "urls": urls, "ruleset": RULESET_VERSION,
            "next_en": nxt[0], "next_hi": nxt[1],
            "note_en": "Risk indicator only. It cannot confirm anything with a bank.",
            "note_hi": "यह केवल जोखिम संकेत है। यह बैंक से कुछ भी पुष्टि नहीं कर सकता।"}
