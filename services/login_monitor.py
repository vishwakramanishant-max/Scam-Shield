"""Failed-login monitor. Reads an allowed log source, groups events, applies thresholds with cautious wording.
It never claims an attack: repeated failures are a signal that needs a human check."""
import re
import shutil
import subprocess
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

RULESET_VERSION = "login-1.0"
LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)"
    r"\s+\S+\s+(?P<proc>[\w\-./]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
FAIL_RES = [re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"),
            re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)")]
OK_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)")
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _parse_ts(s, year):
    s = s.strip()
    if re.match(r"\d{4}-", s):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
        if d.tzinfo:
            d = d.astimezone(timezone.utc).replace(tzinfo=None)
        return d
    m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})", s)
    if not m or m.group(1) not in MONTHS:
        return None
    try:
        return datetime(year, MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
    except ValueError:
        return None


def parse_events(lines, year=None):
    year = year or datetime.now().year
    events = []
    for line in lines:
        m = LINE_RE.match(line.strip())
        if not m or not m.group("proc").lower().startswith(("sshd", "ssh")):
            continue
        ts = _parse_ts(m.group("ts"), year)
        if ts is None:
            continue
        msg = m.group("msg")
        ok = OK_RE.search(msg)
        if ok:
            events.append({"ts": ts, "user": ok.group("user"), "ip": ok.group("ip"), "kind": "success"})
            continue
        for rx in FAIL_RES:
            f = rx.search(msg)
            if f:
                events.append({"ts": ts, "user": f.group("user"), "ip": f.group("ip"), "kind": "fail"})
                break
    return sorted(events, key=lambda e: e["ts"])


def mask_ip(ip):
    if "." in ip:
        return ".".join(ip.split(".")[:3] + ["x"])
    return ip[:9] + "…"


def detect(events, window_s=300, threshold=5, spray_accounts=3):
    """Return findings. A single failure never raises an alert."""
    findings, window = [], timedelta(seconds=window_s)
    by_ip = {}
    for e in events:
        by_ip.setdefault(e["ip"], []).append(e)
    for ip, evs in by_ip.items():
        fails = [e for e in evs if e["kind"] == "fail"]
        for i, start in enumerate(fails):
            group = [f for f in fails[i:] if f["ts"] - start["ts"] <= window]
            if len(group) < min(threshold, spray_accounts):
                continue
            users = {g["user"] for g in group}
            last = group[-1]["ts"]
            success = [e for e in evs if e["kind"] == "success" and last <= e["ts"] <= last + window]
            if success and len(group) >= threshold:
                findings.append(_f("L03", "high", ip, group, users,
                                   "A successful login followed repeated failures from the same source. Confirm it was you; consider changing the password.",
                                   "बार-बार विफलता के बाद उसी स्रोत से सफल लॉगिन हुआ। पुष्टि करें कि यह आप थे; पासवर्ड बदलने पर विचार करें।"))
                break
            if len(group) >= threshold and len(users) < spray_accounts:
                findings.append(_f("L01", "medium", ip, group, users,
                                   f"{len(group)} failed logins in {window_s // 60} minutes from one source (possible password guessing; could also be a user who forgot a password).",
                                   f"{window_s // 60} मिनट में एक स्रोत से {len(group)} विफल लॉगिन (पासवर्ड अनुमान हो सकता है; भूला हुआ पासवर्ड भी हो सकता है)।"))
                break
            if len(users) >= spray_accounts:
                findings.append(_f("L02", "medium", ip, group, users,
                                   f"One source tried {len(users)} different accounts within {window_s // 60} minutes (possible account probing).",
                                   f"एक स्रोत ने {window_s // 60} मिनट में {len(users)} अलग खाते आज़माए (खातों की जाँच-पड़ताल संभव)।"))
                break
    return findings


def _f(rid, sev, ip, group, users, en, hi):
    return {"rule_id": rid, "severity": sev, "source": mask_ip(ip), "accounts": sorted(users)[:5], "count": len(group),
            "first": group[0]["ts"].isoformat(sep=" ", timespec="seconds"), "last": group[-1]["ts"].isoformat(sep=" ", timespec="seconds"),
            "en": en, "hi": hi,
            "action_en": "Review the account, enable key-based SSH login and a firewall rate-limit. No automatic blocking was done.",
            "action_hi": "खाते की समीक्षा करें, SSH में की-आधारित लॉगिन और फ़ायरवॉल सीमा चालू करें। कोई स्वचालित ब्लॉक नहीं किया गया।"}


def read_source(real_log="/var/log/auth.log", sample_log=None, max_lines=2000):
    """Pick the first readable source. Never pretends monitoring is working when it is not."""
    p = Path(real_log)
    if p.exists():
        try:
            with open(p, "r", errors="replace") as fh:
                return {"status": "ACTIVE", "source": str(p), "lines": list(deque(fh, maxlen=max_lines)), "demo": False}
        except PermissionError:
            perm = True
        else:
            perm = False
    else:
        perm = False
    if shutil.which("journalctl"):
        try:
            r = subprocess.run(["journalctl", "-u", "ssh", "-u", "sshd", "--no-pager", "-n", str(max_lines), "-o", "short-iso"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip() and "No entries" not in r.stdout[:80]:
                return {"status": "ACTIVE", "source": "journalctl", "lines": r.stdout.splitlines(), "demo": False}
        except (subprocess.SubprocessError, OSError):
            pass
    if sample_log and Path(sample_log).exists():
        lines = Path(sample_log).read_text(errors="replace").splitlines()
        return {"status": "PERMISSION_REQUIRED" if perm else "DEMO_SAMPLE", "source": Path(sample_log).name, "lines": lines, "demo": True,
                "hint": "Real log not readable. Add the service user to the 'adm' group to read /var/log/auth.log." if perm
                else "No system auth log found; using the synthetic sample log."}
    return {"status": "UNAVAILABLE", "source": None, "lines": [], "demo": False,
            "hint": "No readable log source. Monitoring is NOT active."}


def synth_lines(kind, now=None, n=7):
    """Synthetic lines for the demo. Written only to the sample log, never used against a real service."""
    now = now or datetime.now()
    out = []
    def L(t, msg):
        return f"{t.strftime('%b %e %H:%M:%S')} shopbox sshd[2201]: {msg}"
    if kind == "brute":
        for i in range(n):
            out.append(L(now + timedelta(seconds=i * 6), f"Failed password for admin from 203.0.113.45 port {40000+i} ssh2"))
    elif kind == "spray":
        for i, u in enumerate(["root", "admin", "billing", "test", "pos"]):
            out.append(L(now + timedelta(seconds=i * 8), f"Failed password for invalid user {u} from 198.51.100.77 port {41000+i} ssh2"))
    elif kind == "success_after":
        for i in range(n):
            out.append(L(now + timedelta(seconds=i * 5), f"Failed password for shopkeeper from 203.0.113.99 port {42000+i} ssh2"))
        out.append(L(now + timedelta(seconds=n * 5 + 10), "Accepted password for shopkeeper from 203.0.113.99 port 42100 ssh2"))
    elif kind == "benign":
        out.append(L(now, "Failed password for shopkeeper from 192.0.2.10 port 43000 ssh2"))
        out.append(L(now + timedelta(seconds=20), "Accepted password for shopkeeper from 192.0.2.10 port 43001 ssh2"))
    return out
