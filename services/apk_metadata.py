"""Static APK metadata review. The file is read as a ZIP archive in memory and is NEVER installed or executed.
Permissions are only indicators of risk, not proof of malware."""
import hashlib
import io
import re
import zipfile

RISKY = {
    "READ_SMS": ("Can read your SMS, including bank OTPs.", "आपके SMS, बैंक OTP सहित, पढ़ सकता है।", 30),
    "RECEIVE_SMS": ("Can intercept incoming SMS and OTPs.", "आने वाले SMS और OTP रोक सकता है।", 30),
    "SEND_SMS": ("Can send SMS from your number (can cost money / spread the scam).", "आपके नंबर से SMS भेज सकता है।", 20),
    "BIND_ACCESSIBILITY_SERVICE": ("Accessibility control lets an app watch and tap your screen.", "एक्सेसिबिलिटी से ऐप आपकी स्क्रीन देख और टैप कर सकता है।", 40),
    "SYSTEM_ALERT_WINDOW": ("Can draw fake screens over your banking app.", "बैंकिंग ऐप के ऊपर नकली स्क्रीन दिखा सकता है।", 25),
    "REQUEST_INSTALL_PACKAGES": ("Can install other apps.", "दूसरे ऐप इंस्टॉल कर सकता है।", 25),
    "BIND_DEVICE_ADMIN": ("Can lock the device and resist removal.", "डिवाइस लॉक कर सकता है और हटाने में बाधा डाल सकता है।", 30),
    "READ_CONTACTS": ("Can read your contacts.", "आपके संपर्क पढ़ सकता है।", 10),
    "RECORD_AUDIO": ("Can record audio.", "ऑडियो रिकॉर्ड कर सकता है।", 10),
    "READ_CALL_LOG": ("Can read your call history.", "कॉल हिस्ट्री पढ़ सकता है।", 15),
}
LURE_NAME = re.compile(r"(?i)(kyc|update|sbi|hdfc|icici|axis|paytm|phonepe|reward|refund|rto|challan|pm[_-]?kisan|gas[_-]?bill|electricity)")
MAX_BYTES = 10 * 1024 * 1024


def inspect(data: bytes, filename="app.apk"):
    if len(data) > MAX_BYTES:
        return {"ok": False, "error": "File too large for this check (10 MB limit)."}
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return {"ok": False, "error": "Not a valid APK/ZIP archive."}
    perms, names = set(), []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()[:5000]
        manifest = z.read("AndroidManifest.xml") if "AndroidManifest.xml" in names else b""
    blob = manifest + manifest.replace(b"\x00", b"")
    for m in re.finditer(rb"android\.permission\.([A-Z_]{4,60})", blob):
        perms.add(m.group(1).decode())
    reasons, score = [], 0
    for p in sorted(perms):
        if p in RISKY:
            en, hi, w = RISKY[p]
            score += w
            reasons.append({"id": "A01", "permission": p, "en": en, "hi": hi})
    if LURE_NAME.search(filename):
        score += 20
        reasons.append({"id": "A02", "en": "File name looks like a bank/government lure typically forwarded on WhatsApp.",
                        "hi": "फ़ाइल का नाम बैंक/सरकारी लालच जैसा है, जो अक्सर WhatsApp पर फैलता है।"})
    if "AndroidManifest.xml" not in names:
        reasons.append({"id": "A03", "en": "No AndroidManifest.xml found; the file may not be a genuine app.", "hi": "AndroidManifest.xml नहीं मिला; फ़ाइल असली ऐप नहीं हो सकती।"})
        score += 10
    level = "High" if score >= 60 else "Medium" if score >= 25 else "Low"
    return {"ok": True, "level": level, "score": min(score, 100), "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data), "dex_files": sum(1 for n in names if n.endswith(".dex")),
            "permissions_found": sorted(perms), "reasons": reasons,
            "note_en": "Static metadata review only. The app was not installed or run. Install apps only from the official store.",
            "note_hi": "केवल स्थिर मेटाडेटा जाँच। ऐप इंस्टॉल या चलाया नहीं गया। ऐप केवल आधिकारिक स्टोर से इंस्टॉल करें।"}
