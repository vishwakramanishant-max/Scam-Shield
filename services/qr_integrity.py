"""QR payload decoding and comparison with the shop's registered UPI identifiers.
A software check cannot see a sticker; it detects that the payload being scanned is not the registered one."""
import re
from urllib.parse import urlparse, parse_qs, unquote

import numpy as np

from .url_risk import registrable, SHORTENERS

UPI_ID_RE = re.compile(r"^[A-Za-z0-9.\-_]{2,256}@[A-Za-z][A-Za-z0-9]{1,63}$")


def decode_image(data: bytes):
    """Return decoded QR text or None. Image bytes are only decoded, never executed or saved."""
    import cv2
    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return None
    detectors = [cv2.QRCodeDetector()]
    if hasattr(cv2, "QRCodeDetectorAruco"):
        detectors.append(cv2.QRCodeDetectorAruco())
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    variants = [img, gray]
    for s in (0.5, 0.75, 1.5, 2.0, 3.0):
        variants.append(cv2.resize(gray, None, fx=s, fy=s, interpolation=cv2.INTER_AREA if s < 1 else cv2.INTER_CUBIC))
    variants.append(cv2.copyMakeBorder(gray, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255))
    for det in detectors:
        for v in variants:
            try:
                text, _, _ = det.detectAndDecode(v)
            except cv2.error:
                continue
            if text:
                return text
    return None


def parse_payload(payload):
    p = (payload or "").strip()
    if not p:
        return {"kind": "empty"}
    if p.lower().startswith("upi://"):
        q = parse_qs(urlparse(p).query, keep_blank_values=True)
        q = {k.lower(): [unquote(x) for x in v] for k, v in q.items()}
        pa = q.get("pa", [""])
        return {"kind": "upi", "pa": pa[0].strip(), "pn": (q.get("pn", [""])[0]).strip(),
                "am": (q.get("am", [""])[0]).strip(), "duplicate_pa": len(pa) > 1,
                "pa_values": pa}
    if re.match(r"(?i)^(https?://|www\.)", p):
        host = (urlparse(p if "://" in p else "http://" + p).hostname or "")
        return {"kind": "url", "host": host, "shortened": registrable(host) in SHORTENERS}
    return {"kind": "other", "preview": p[:40]}


def _norm_name(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _dist(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def compare(payload, registered):
    """registered: list of {label, upi_id, payee_name}. Returns status + evidence."""
    parsed = parse_payload(payload)
    res = {"parsed_kind": parsed["kind"], "flags": [], "expected": [r["upi_id"] for r in registered]}
    if parsed["kind"] in ("empty",):
        res.update(status="UNABLE_TO_PARSE", en="No QR could be read. Verify the payee inside your payment app.",
                   hi="QR पढ़ा नहीं जा सका। अपने पेमेंट ऐप में पाने वाले का नाम जाँचें।")
        return res
    if parsed["kind"] in ("url", "other"):
        note = " It is a shortened link." if parsed.get("shortened") else ""
        res.update(status="NOT_UPI", observed=parsed.get("host") or parsed.get("preview"),
                   en="This QR does not contain a UPI payment address, so it is not your payment QR." + note,
                   hi="इस QR में UPI भुगतान पता नहीं है, इसलिए यह आपका भुगतान QR नहीं है।")
        return res
    pa = parsed["pa"]
    res["observed"] = pa
    res["observed_name"] = parsed["pn"]
    if not pa or not UPI_ID_RE.match(pa):
        res.update(status="UNABLE_TO_PARSE", en="QR looks like UPI but the payment address is missing or malformed.",
                   hi="QR UPI जैसा है पर भुगतान पता गायब या गलत है।")
        return res
    if parsed["duplicate_pa"] and len(set(v.lower() for v in parsed["pa_values"])) > 1:
        res["flags"].append("duplicate_pa")
    if parsed["am"]:
        res["flags"].append("fixed_amount")
    reg_ids = {r["upi_id"].lower(): r for r in registered}
    if "duplicate_pa" in res["flags"]:
        res.update(status="MISMATCH", en="QR contains more than one payee address, which is abnormal. Do not accept payments to it.",
                   hi="QR में एक से ज़्यादा भुगतान पते हैं, जो असामान्य है। इसमें भुगतान न लें।")
        return res
    hit = reg_ids.get(pa.lower())
    if hit:
        exp_name = _norm_name(hit.get("payee_name"))
        seen_name = _norm_name(parsed["pn"])
        if exp_name and seen_name and exp_name != seen_name:
            res.update(status="PARTIAL", expected_name=hit.get("payee_name"),
                       en=f"Payment address matches, but the payee name differs (expected '{hit.get('payee_name')}', QR says '{parsed['pn']}'). Check before accepting.",
                       hi=f"पता मेल खाता है, पर नाम अलग है (अपेक्षित '{hit.get('payee_name')}', QR में '{parsed['pn']}')। स्वीकार करने से पहले जाँचें।")
        else:
            res.update(status="MATCH", en="Payment address matches a registered QR. This confirms the QR content, not that any payment arrived.",
                       hi="भुगतान पता पंजीकृत QR से मेल खाता है। यह QR की सामग्री की पुष्टि है, भुगतान आने की नहीं।")
        return res
    close = [r["upi_id"] for r in registered if _dist(pa.lower(), r["upi_id"].lower()) <= 2]
    if close:
        res["flags"].append("look_alike_of_registered")
    res.update(status="MISMATCH", closest=close[:1],
               en="This QR pays a DIFFERENT address than your registered one." + (" It looks very similar to yours, a common swap trick." if close else ""),
               hi="यह QR आपके पंजीकृत पते से अलग पते पर पैसे भेजता है।" + (" यह आपके पते जैसा दिखता है, जो बदलने की आम चाल है।" if close else ""))
    return res
