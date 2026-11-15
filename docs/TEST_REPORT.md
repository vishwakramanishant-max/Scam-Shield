# Scam Shield: Test Report

Generated 2026-11-14 12:53 by `python -m tests.metrics` · Python 3.13.18 · rulesets msg-1.0, url-1.0

> The labelled sets are small and written by the author. These numbers are a sanity benchmark for this prototype, **not** a claim about accuracy on real-world scams.

## 1. Automated test suite

| Test file | Passed | Total |
|---|---|---|
| test_app | 18 | 18 |
| test_detection | 10 | 10 |
| test_modules | 33 | 33 |
| **All** | **61** | **61** |

## 2. Detection metrics on the labelled sets

| Engine | Cases | Precision | Recall | False-positive rate | TP | FP | FN | TN | Median latency |
|---|---|---|---|---|---|---|---|---|---|
| Message analyser (all cases) | 61 | 93.1% | 90.0% | 6.5% | 27 | 2 | 3 | 29 | 0.06 ms |
| Message analyser (excluding 'hard' cases) | 55 | 100.0% | 100.0% | 0.0% | 27 | 0 | 0 | 28 | 0.06 ms |
| URL risk | 26 | 100.0% | 100.0% | 0.0% | 12 | 0 | 0 | 14 | 0.04 ms |

A case counts as *flagged* when the level is Medium or High.

## 3. Known misses and false alarms (shown, not hidden)

**Missed scam messages (false negatives): 3**
- [hard] `Sir please check this link for your parcel status http://parcel-track-india.xyz` → Low
- [hard] `Your son has been arrested. Pay bail now to this number or he will be jailed.` → Low
- [hard] `Kindly send your Aadhaar and PAN photos to complete the refund formalities.` → Low

**Genuine messages wrongly flagged (false positives): 2**
- [hard] `Join our store loyalty programme and earn reward points on every purchase.` → Medium
- [hard] `Awareness tip: approving a collect request sends money out, so only approve one if you expect to pay.` → Medium

**URL misses / false alarms:** none

## 4. What the suite proves about the ChatGPT-review concerns

| Concern | Evidence (test) |
|---|---|
| Screenshot alone must never be 'Verified' | `test_screenshot_alone_is_never_verified` |
| Warnings must not claim safety or settlement | `test_low_wording_never_says_safe`, `test_unmatched_wording_does_not_claim_fraud_or_settlement`, `test_qr_match_wording_does_not_claim_payment` |
| Secrets must be redacted everywhere | `test_scanner_finds_masks_and_ignores_placeholders`, `test_secret_scan_alerts_are_masked_and_fix_flow` |
| Fixes need approval, backup, valid result | `test_fix_requires_approval_backs_up_and_shows_diff` |
| Path traversal / symlink escape blocked | `test_scanner_blocks_path_traversal_and_outside_roots` |
| Single failed login is not an attack | `test_single_failure_and_typo_are_not_alerts` |
| Factory module cannot control machines | `test_iot_alerts_state_the_safe_boundary_and_module_has_no_control_path` |
| Auth, CSRF, hashed passwords, throttle | `test_auth_required_everywhere`, `test_csrf_is_enforced`, `test_setup_rules_and_login_throttle` |
| Upload limits and type checks | `test_qr_flow_uploads_and_validation`, `test_csv_import_validation`, `test_apk_benign_and_invalid` |
| Pasted text is not stored | `test_analyze_creates_alert_but_does_not_store_text` |
| Transparent readiness (no hidden percentage) | `test_readiness_is_transparent_and_never_a_percentage` |
| Detection never touches the network | `test_url_never_fetches` |
| CSV export is spreadsheet-injection safe | `test_alert_ack_filter_and_csv_export_is_injection_safe` |
