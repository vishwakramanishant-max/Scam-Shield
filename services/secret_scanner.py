"""Secret and insecure-code scanner. Scans only inside allowed roots, redacts every value it reports,
and offers fixes as human-approved diffs with a backup (never silent rewrites)."""
import difflib
import math
import os
import re
import shutil
import time
from pathlib import Path

RULESET_VERSION = "sec-1.0"
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 2000
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".idea", "dist", "build"}
TEXT_EXT = {".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".ini", ".cfg", ".conf", ".txt", ".md",
            ".sh", ".php", ".java", ".properties", ".toml", ".html", ".xml", ".csv", ""}
PLACEHOLDER = re.compile(r"(changeme|example|your[_-]|xxxx|<.*>|\$\{|os\.environ|getenv|process\.env|\*{3,}|dummy|placeholder|sample)", re.I)

SECRET_RULES = [
    ("S001", "AWS access key id", "high", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("S002", "Private key block", "high", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)")),
    ("S003", "Google API key", "high", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("S004", "GitHub token", "high", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b")),
    ("S005", "Slack token", "high", re.compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b")),
    ("S006", "Hard-coded credential", "medium",
     re.compile(r"(?i)[A-Za-z0-9_\-]*(?:api[_-]?key|secret|token|passwd|password|pwd|auth)[A-Za-z0-9_\-]*[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']")),
    ("S007", "Credential in connection string", "high", re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:([^/\s:@]{4,})@")),
]
CODE_RULES = [
    ("C001", "eval/exec on dynamic input", "medium", re.compile(r"\b(?:eval|exec)\s*\("), "Avoid eval/exec; parse data with json/ast.literal_eval."),
    ("C002", "Shell command with shell=True", "medium", re.compile(r"shell\s*=\s*True"), "Pass a list of arguments and drop shell=True."),
    ("C003", "TLS verification disabled", "medium", re.compile(r"verify\s*=\s*False"), "Keep certificate verification on."),
    ("C004", "Debug mode enabled", "low", re.compile(r"debug\s*=\s*True"), "Turn debug off outside local development."),
    ("C005", "Weak hash (MD5/SHA1)", "low", re.compile(r"hashlib\.(?:md5|sha1)\("), "Use SHA-256 or a password hasher (bcrypt/argon2)."),
    ("C006", "SQL built from strings", "medium", re.compile(r"(?i)execute\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+|\.format))"), "Use parameterised queries."),
    ("C007", "Unsafe deserialisation", "medium", re.compile(r"\bpickle\.loads?\(|yaml\.load\((?![^)]*Loader)"), "Use json or yaml.safe_load."),
]
CONFIG_EXT = (".env", ".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".toml")
# unquoted KEY=value lines, only trusted in config-style files
S006_UNQUOTED = re.compile(r"(?i)^\s*[A-Za-z0-9_\-]*(?:api[_-]?key|secret|token|passwd|password|pwd|auth)[A-Za-z0-9_\-]*\s*[:=]\s*([^\s\"'#]{8,})\s*$")
LABEL_HI = {"AWS access key id": "AWS एक्सेस कुंजी", "Private key block": "प्राइवेट की ब्लॉक", "Google API key": "Google API कुंजी",
            "GitHub token": "GitHub टोकन", "Slack token": "Slack टोकन", "Hard-coded credential": "कोड में लिखा पासवर्ड/कुंजी",
            "Credential in connection string": "कनेक्शन स्ट्रिंग में पासवर्ड", "eval/exec on dynamic input": "eval/exec का उपयोग",
            "Shell command with shell=True": "shell=True वाला कमांड", "TLS verification disabled": "TLS सत्यापन बंद",
            "Debug mode enabled": "डिबग मोड चालू", "Weak hash (MD5/SHA1)": "कमज़ोर हैश (MD5/SHA1)",
            "SQL built from strings": "स्ट्रिंग से बनी SQL क्वेरी", "Unsafe deserialisation": "असुरक्षित डीसीरियलाइज़ेशन"}
ADVICE_HI = {"C001": "eval/exec से बचें; डेटा के लिए json या ast.literal_eval इस्तेमाल करें।", "C002": "आर्ग्युमेंट की सूची दें और shell=True हटाएँ।",
             "C003": "प्रमाणपत्र सत्यापन चालू रखें।", "C004": "स्थानीय विकास के बाहर डिबग बंद रखें।",
             "C005": "SHA-256 या पासवर्ड हैशर (bcrypt/argon2) इस्तेमाल करें।", "C006": "पैरामीटर वाली क्वेरी इस्तेमाल करें।", "C007": "json या yaml.safe_load इस्तेमाल करें।"}
ADVICE_SECRET_HI = "कुंजी तुरंत बदलें (मानें कि वह लीक हो चुकी है), उसे पर्यावरण चर या सीक्रेट मैनेजर में रखें, और फ़ाइल को वर्ज़न कंट्रोल से बाहर रखें।"
ADVICE_SECRET = ("Rotate this key now (assume it is exposed), move it to an environment variable or secrets manager, "
                 "and keep the file out of version control.")


def entropy(s):
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def mask(value):
    v = value.strip()
    if len(v) <= 6:
        return "*" * len(v)
    return v[:3] + "*" * min(12, len(v) - 3) + f" (len {len(v)})"


def safe_root(path, allowed_roots):
    """Resolve path and ensure it is inside one of the allowed roots (blocks ../ traversal and symlink escape)."""
    try:
        real = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    for root in allowed_roots:
        try:
            r = Path(root).resolve()
        except OSError:
            continue
        if real == r or r in real.parents:
            return real
    return None


def _looks_binary(b):
    return b"\x00" in b[:2048]


def scan_text(text, relname):
    findings = []
    for ln, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            continue
        for rid, label, sev, rx in SECRET_RULES:
            m = rx.search(line)
            if not m:
                continue
            val = m.group(1)
            if PLACEHOLDER.search(line) or PLACEHOLDER.search(val):
                continue
            if rid in ("S006", "S007") and entropy(val) < 2.8:
                continue
            findings.append({"rule_id": rid, "type": label, "severity": sev, "file": relname, "line": ln,
                             "masked": mask(val), "kind": "secret", "advice": ADVICE_SECRET, "advice_hi": ADVICE_SECRET_HI,
                             "type_hi": LABEL_HI[label], "fixable": relname.endswith(".py") and rid in ("S006",)})
        if relname.lower().endswith(CONFIG_EXT):
            m = S006_UNQUOTED.match(line)
            if m and not PLACEHOLDER.search(line) and entropy(m.group(1)) >= 2.8 and \
                    not any(f["line"] == ln and f["kind"] == "secret" for f in findings):
                findings.append({"rule_id": "S006", "type": "Hard-coded credential", "severity": "medium", "file": relname,
                                 "line": ln, "masked": mask(m.group(1)), "kind": "secret", "advice": ADVICE_SECRET, "advice_hi": ADVICE_SECRET_HI,
                                 "type_hi": LABEL_HI["Hard-coded credential"], "fixable": False})
        for rid, label, sev, rx, advice in CODE_RULES:
            if rx.search(line) and not line.lstrip().startswith(("#", "//")):
                findings.append({"rule_id": rid, "type": label, "severity": sev, "file": relname, "line": ln,
                                 "masked": line.strip()[:60], "kind": "code", "advice": advice, "advice_hi": ADVICE_HI[rid],
                                 "type_hi": LABEL_HI[label], "fixable": False})
    return findings


def scan(root, allowed_roots):
    t0 = time.time()
    real = safe_root(root, allowed_roots)
    if real is None:
        return {"ok": False, "error": "Path is outside the allowed scan folders or does not exist."}
    findings, files, skipped = [], 0, 0
    for dirpath, dirnames, filenames in os.walk(real, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if files >= MAX_FILES:
                skipped += 1
                continue
            fp = Path(dirpath) / fn
            if fp.suffix.lower() not in TEXT_EXT or fp.is_symlink():
                skipped += 1
                continue
            try:
                if fp.stat().st_size > MAX_FILE_BYTES:
                    skipped += 1
                    continue
                data = fp.read_bytes()
            except OSError:
                skipped += 1
                continue
            if _looks_binary(data):
                skipped += 1
                continue
            files += 1
            findings += scan_text(data.decode("utf-8", errors="replace"), str(fp.relative_to(real)))
    return {"ok": True, "root": str(real), "files_scanned": files, "files_skipped": skipped, "findings": findings,
            "seconds": round(time.time() - t0, 3), "ruleset": RULESET_VERSION}


ASSIGN_RE = re.compile(r"""^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(["'])(.+?)\3\s*(#.*)?$""")


def propose_fix(root, relfile, line_no, allowed_roots):
    """Return a unified diff replacing a hard-coded Python literal with os.environ.get(...). Does not write."""
    base = safe_root(root, allowed_roots)
    if base is None:
        return {"ok": False, "error": "Folder not allowed."}
    target = (base / relfile).resolve()
    if base not in target.parents or target.suffix != ".py" or not target.is_file():
        return {"ok": False, "error": "Automatic fix is offered only for .py files inside the scanned folder."}
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    if not (1 <= line_no <= len(lines)):
        return {"ok": False, "error": "Line not found."}
    m = ASSIGN_RE.match(lines[line_no - 1].rstrip("\n"))
    if not m or not [f for f in scan_text(lines[line_no - 1], target.name) if f["rule_id"] == "S006"]:
        return {"ok": False, "error": "This line is not a simple hard-coded assignment; follow the manual advice instead."}
    indent, name = m.group(1), m.group(2)
    env = name.upper()
    new = list(lines)
    new[line_no - 1] = f'{indent}{name} = os.environ.get("{env}", "")\n'
    if not any(re.match(r"\s*import os\b", l) for l in lines):
        new.insert(0, "import os\n")
    # the displayed diff must never reveal the secret: mask the literal on the removed line
    shown_old = list(lines)
    shown_old[line_no - 1] = lines[line_no - 1].replace(m.group(4), mask(m.group(4)))
    diff = "".join(difflib.unified_diff(shown_old, new, f"a/{relfile}", f"b/{relfile}"))
    return {"ok": True, "diff": diff, "env_var": env, "new_lines": new,
            "note": f"After applying, set {env} in your environment and rotate the old key; it remains in your file history."}


def apply_fix(root, relfile, line_no, allowed_roots, approved=False):
    if not approved:
        return {"ok": False, "error": "Human approval is required."}
    prop = propose_fix(root, relfile, line_no, allowed_roots)
    if not prop["ok"]:
        return prop
    base = safe_root(root, allowed_roots)
    target = (base / relfile).resolve()
    backup = target.with_name(target.name + f".bak.{int(time.time())}")
    shutil.copy2(target, backup)
    target.write_text("".join(prop["new_lines"]), encoding="utf-8")
    return {"ok": True, "diff": prop["diff"], "backup": backup.name, "env_var": prop["env_var"], "note": prop["note"]}
