# Security and Privacy Checklist

Each line names the control and the automated test that checks it (✔ = test exists and passes in `docs/TEST_REPORT.md`).
Items marked **Not done** are stated openly.

| # | Control | Status | Evidence |
|---|---|---|---|
| 1 | Dashboard requires login; first-run setup closes after the owner exists | ✔ | `test_auth_required_everywhere`, `test_setup_rules_and_login_throttle` |
| 2 | Passwords hashed (scrypt/pbkdf2), never stored in clear | ✔ | `test_setup_rules_and_login_throttle` |
| 3 | Login throttling (5 failures → 60 s lock, even for the right password) | ✔ | `test_setup_rules_and_login_throttle` |
| 4 | CSRF token required on every POST/PUT/DELETE | ✔ | `test_csrf_is_enforced` |
| 5 | HttpOnly + SameSite=Lax session cookie, 8 h lifetime, random secret key file (0600) | ✔ | `config.py`, `app.py` |
| 6 | CSP `script-src 'self'`, `frame-ancestors 'none'`, nosniff, no-referrer, no-store on API | ✔ | `test_security_headers_and_no_store` |
| 7 | Binds to 127.0.0.1 by default; warning printed if exposed | ✔ | `app.py` |
| 8 | Upload limits (2 MB image, 1 MB CSV, 10 MB APK) and type checks; uploads never executed or saved | ✔ | `test_qr_flow_uploads_and_validation`, `test_csv_import_validation`, `test_apk_benign_and_invalid` |
| 9 | Scan roots allow-list; `../` traversal and symlink escape blocked | ✔ | `test_scanner_blocks_path_traversal_and_outside_roots` |
| 10 | Secrets masked in findings, alerts, API and fix diffs | ✔ | `test_scanner_finds_masks_and_ignores_placeholders`, `test_fix_requires_approval_backs_up_and_shows_diff` |
| 11 | Fixes need explicit approval, make a backup, show a diff, stay valid Python | ✔ | `test_fix_requires_approval_backs_up_and_shows_diff` |
| 12 | Pasted messages analysed but not stored (only rule IDs + length kept) | ✔ | `test_analyze_creates_alert_but_does_not_store_text` |
| 13 | Detection code makes no network calls (URLs are never fetched) | ✔ | `test_url_never_fetches` |
| 14 | Login-monitor IPs masked in display; single failures never alerted | ✔ | `test_brute_force_flagged_with_cautious_wording`, `test_single_failure_and_typo_are_not_alerts` |
| 15 | Voice alerts never speak pasted/sensitive text; written warning always shown; mute switch | ✔ | `static/app.js` (`speak()`), reviewed |
| 16 | No call recording / listening / message interception | ✔ | by design; `services/voice_safety.py` consent text |
| 17 | Factory module has no control path (no socket/serial/subprocess) | ✔ | `test_iot_alerts_state_the_safe_boundary_and_module_has_no_control_path` |
| 18 | CSV export safe against spreadsheet formula injection | ✔ | `test_alert_ack_filter_and_csv_export_is_injection_safe` |
| 19 | SQL uses parameterised queries only | ✔ | `app.py`, `db.py` (code review) |
| 20 | Readiness shows "Not assessed / Stale", never a hidden percentage | ✔ | `test_readiness_is_transparent_and_never_a_percentage` |
| 21 | HTTPS | **Not done** | Use a reverse proxy (Caddy/nginx) for any phone access beyond localhost |
| 22 | Multi-user roles, password reset, audit-log viewer | **Not done** | Single owner account; audit rows are written to the DB but have no UI |
| 23 | Encryption of the SQLite file at rest | **Not done** | Rely on disk encryption (LUKS); minimal data is stored by design |
| 24 | Independent security review / penetration test | **Not done** | Self-tested only |

Responsible-use boundary: all demos use dummy QR codes, fake keys, made-up transactions, generated log lines and a simulated machine.
Do not point the login demo, scanner or any tool at real accounts, systems or devices you do not own.
