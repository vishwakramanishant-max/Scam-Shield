"""Measure the detection engines on the labelled set and write docs/TEST_REPORT.md from the REAL run.
Usage:  python -m tests.metrics
Nothing in the report is typed by hand; every number comes from this run."""
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from statistics import median

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from services import upi_risk, url_risk                      # noqa: E402
from tests.dataset import MESSAGES, URLS                      # noqa: E402


def confusion(items, fn):
    tp = fp = fn_ = tn = 0
    misses, false_alarms, lat = [], [], []
    for text, label, hard in items:
        t0 = time.perf_counter()
        level = fn(text)
        lat.append((time.perf_counter() - t0) * 1000)
        flagged = level in ("Medium", "High")
        if flagged and label: tp += 1
        elif flagged and not label: fp += 1; false_alarms.append((text, level, hard))
        elif not flagged and label: fn_ += 1; misses.append((text, level, hard))
        else: tn += 1
    return dict(tp=tp, fp=fp, fn=fn_, tn=tn, misses=misses, false_alarms=false_alarms, lat=lat,
                precision=tp / (tp + fp) if tp + fp else 0, recall=tp / (tp + fn_) if tp + fn_ else 0,
                fpr=fp / (fp + tn) if fp + tn else 0)


def pct(x):
    return f"{x * 100:.1f}%"


def main():
    m = confusion(MESSAGES, lambda t: upi_risk.analyze(t)["level"])
    u = confusion(URLS, lambda t: url_risk.analyze(t)["level"])
    easy = [x for x in MESSAGES if not x[2]]
    me = confusion(easy, lambda t: upi_risk.analyze(t)["level"])

    junit = ROOT / "docs" / "junit.xml"
    subprocess.run([sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider", f"--junitxml={junit}"],
                   cwd=ROOT, capture_output=True, text=True)
    suite = ET.parse(junit).getroot()
    suite = suite.find("testsuite") if suite.tag == "testsuites" else suite
    cases = [(c.get("classname", "").split(".")[-1], c.get("name"), c.find("failure") is None and c.find("error") is None) for c in suite.iter("testcase")]
    by_file = {}
    for f, n, ok in cases:
        p, t = by_file.get(f, (0, 0)); by_file[f] = (p + ok, t + 1)

    md = [f"# Scam Shield: Test Report", "",
          f"Generated {datetime.now():%Y-%m-%d %H:%M} by `python -m tests.metrics` · Python {sys.version.split()[0]} · "
          f"rulesets {upi_risk.RULESET_VERSION}, {url_risk.RULESET_VERSION}", "",
          "> The labelled sets are small and written by the author. These numbers are a sanity benchmark for this prototype, "
          "**not** a claim about accuracy on real-world scams.", "",
          "## 1. Automated test suite", "", "| Test file | Passed | Total |", "|---|---|---|"]
    for f, (p, t) in sorted(by_file.items()):
        md.append(f"| {f} | {p} | {t} |")
    tp_, tt_ = sum(p for p, _ in by_file.values()), sum(t for _, t in by_file.values())
    md += [f"| **All** | **{tp_}** | **{tt_}** |", "",
           "## 2. Detection metrics on the labelled sets", "",
           "| Engine | Cases | Precision | Recall | False-positive rate | TP | FP | FN | TN | Median latency |", "|---|---|---|---|---|---|---|---|---|---|",
           f"| Message analyser (all cases) | {len(MESSAGES)} | {pct(m['precision'])} | {pct(m['recall'])} | {pct(m['fpr'])} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {median(m['lat']):.2f} ms |",
           f"| Message analyser (excluding 'hard' cases) | {len(easy)} | {pct(me['precision'])} | {pct(me['recall'])} | {pct(me['fpr'])} | {me['tp']} | {me['fp']} | {me['fn']} | {me['tn']} | {median(me['lat']):.2f} ms |",
           f"| URL risk | {len(URLS)} | {pct(u['precision'])} | {pct(u['recall'])} | {pct(u['fpr'])} | {u['tp']} | {u['fp']} | {u['fn']} | {u['tn']} | {median(u['lat']):.2f} ms |", "",
           "A case counts as *flagged* when the level is Medium or High.", "",
           "## 3. Known misses and false alarms (shown, not hidden)", ""]
    for title, rows in (("Missed scam messages (false negatives)", m["misses"]), ("Genuine messages wrongly flagged (false positives)", m["false_alarms"])):
        md.append(f"**{title}: {len(rows)}**")
        md += [f"- {'[hard] ' if h else ''}`{t[:110]}` → {lvl}" for t, lvl, h in rows] or ["- none"]
        md.append("")
    md.append("**URL misses / false alarms:** " + (", ".join(f"`{t}`" for t, *_ in u["misses"] + u["false_alarms"]) or "none"))
    md += ["", "## 4. What the suite proves about the ChatGPT-review concerns", "",
           "| Concern | Evidence (test) |", "|---|---|",
           "| Screenshot alone must never be 'Verified' | `test_screenshot_alone_is_never_verified` |",
           "| Warnings must not claim safety or settlement | `test_low_wording_never_says_safe`, `test_unmatched_wording_does_not_claim_fraud_or_settlement`, `test_qr_match_wording_does_not_claim_payment` |",
           "| Secrets must be redacted everywhere | `test_scanner_finds_masks_and_ignores_placeholders`, `test_secret_scan_alerts_are_masked_and_fix_flow` |",
           "| Fixes need approval, backup, valid result | `test_fix_requires_approval_backs_up_and_shows_diff` |",
           "| Path traversal / symlink escape blocked | `test_scanner_blocks_path_traversal_and_outside_roots` |",
           "| Single failed login is not an attack | `test_single_failure_and_typo_are_not_alerts` |",
           "| Factory module cannot control machines | `test_iot_alerts_state_the_safe_boundary_and_module_has_no_control_path` |",
           "| Auth, CSRF, hashed passwords, throttle | `test_auth_required_everywhere`, `test_csrf_is_enforced`, `test_setup_rules_and_login_throttle` |",
           "| Upload limits and type checks | `test_qr_flow_uploads_and_validation`, `test_csv_import_validation`, `test_apk_benign_and_invalid` |",
           "| Pasted text is not stored | `test_analyze_creates_alert_but_does_not_store_text` |",
           "| Transparent readiness (no hidden percentage) | `test_readiness_is_transparent_and_never_a_percentage` |",
           "| Detection never touches the network | `test_url_never_fetches` |",
           "| CSV export is spreadsheet-injection safe | `test_alert_ack_filter_and_csv_export_is_injection_safe` |", ""]
    out = ROOT / "docs" / "TEST_REPORT.md"
    out.write_text("\n".join(md))
    print("\n".join(md[:30]))
    print(f"\nwritten: {out}")
    return m, u, me, (tp_, tt_)


if __name__ == "__main__":
    main()
