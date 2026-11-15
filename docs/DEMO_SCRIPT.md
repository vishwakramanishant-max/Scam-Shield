# 5-Minute Live Demo Script

**Before you start (2 min):** `python make_samples.py` → `python app.py` → create the owner account → click **Reset demo**, then **Load demo data**.
Open the page in the exact browser you will present in. Tick **Voice alerts** and test Hindi once. Keep a screen recording as backup.

| Time | Do this | Judges see | Say |
|---|---|---|---|
| 0:00–0:30 | Overview tab | Readiness table: everything "Not assessed" or "Incomplete" | "Scam Shield tells the truth: if a check has not run, it says so. It detects, explains, recommends and records." |
| 0:30–1:15 | **Messages & Links** → *Insert sample scam* → Analyse | High risk, reason codes U01/U09/U12, Hindi/English text, voice alert | "Every flag has a rule ID and a reason. It is a risk indicator, not a verdict." Then click *Insert sample genuine* → **Low**, "not a guarantee". |
| 1:15–2:00 | **QR & Payments** → upload `qr/02_lookalike_swapped_qr.png` | MISMATCH, "looks very similar to yours" with expected vs observed ID | "We cannot see a sticker. We catch the result of a swap." Then upload `01_genuine_shop_qr.png` → MATCH ("confirms the QR, not that a payment arrived"). |
| 2:00–2:40 | **Reconcile now** (demo data already loaded) | 3 Matched, 1 Pending, 1 **Unmatched Rs 999** → alert "scan your QR now"; duplicate and refund noted | "It only says what the imported statement contains. It never claims settlement." Tick *only screenshot* → **Not verified**. |
| 2:40–3:40 | **Linux Guard** → Scan folder → *Suggest fix* → show diff (secret masked) → **Check logins** → *Demo: repeated failures* | Masked secrets with file:line; diff + approval button; login alert marked **demo log**, IP masked | "Secrets are never shown. Fixes need approval and make a backup. A single typo is not an attack" (click *one typo* → no alert). |
| 3:40–4:20 | **Factory** → Normal ×2 → *Inject overheating* ×3 → *Device goes silent* | Chart crossing 85 °C, I01/I03 high alert, I04 heartbeat alert, **SIMULATED** banner | "Alerts only. This module has no way to control a machine." |
| 4:20–5:00 | **Overview** → *Run all automatic checks* → switch to Hindi → Alerts & History | Readiness = Action needed with reasons; alert history; Export CSV | "One place for alerts, in Hindi and English. Limits are in the README: rule-based, simulated factory, no bank confirmation." |

**Optional extras if time allows:** Citizen Safety tab (call-back steps + self-check), APK check with `SBI_KYC_Update_FAKE_SAMPLE.apk`, `python worker.py --once` in a terminal.

**If something fails:** the written warning always works even if voice does not; use the screen recording; every demo file is synthetic so nothing needs cleaning up except *Reset demo*.
