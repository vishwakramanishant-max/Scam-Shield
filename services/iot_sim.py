"""SIMULATED factory telemetry and read-only anomaly rules.
This module has no control path: it cannot send commands to, stop or modify any machine. Alerts only."""
import random
from datetime import datetime, timedelta

RULESET_VERSION = "iot-1.0"
DEVICE = "Pump-01 (SIMULATED)"
RANGES = {"temp_c": (20.0, 85.0), "vibration_mm_s": (0.0, 7.0), "current_a": (2.0, 15.0)}
WARN = {"temp_c": 75.0, "vibration_mm_s": 5.5, "current_a": 13.0}
JUMP_TEMP = 15.0
HEARTBEAT_TIMEOUT_S = 30
SAFE_BOUNDARY = "Alerts only. This prototype sends no control commands and cannot stop or change any machine."
MODES = ("normal", "overheat", "vibration", "heartbeat_loss")


def next_reading(prev, mode, rng=None, now=None):
    """Generate the next simulated reading, or None for heartbeat_loss (the device 'goes silent')."""
    rng = rng or random
    now = now or datetime.now()
    if mode == "heartbeat_loss":
        return None
    t = prev["temp_c"] if prev else 60.0
    if mode == "overheat":
        temp = min(t + rng.uniform(10, 14), 110.0) if t > 70 else t + rng.uniform(12, 16)
    else:
        temp = 60.0 + rng.uniform(-3, 3)
    vib = rng.uniform(8.5, 11.0) if mode == "vibration" else 3.0 + rng.uniform(-0.6, 0.6)
    cur = 9.0 + rng.uniform(-0.8, 0.8)
    return {"ts": now, "temp_c": round(temp, 1), "vibration_mm_s": round(vib, 2), "current_a": round(cur, 2)}


def _R(rid, sev, en, hi, ev):
    return {"rule_id": rid, "severity": sev, "en": en, "hi": hi, "evidence": ev,
            "action_en": "Operator inspection recommended. " + SAFE_BOUNDARY,
            "action_hi": "ऑपरेटर द्वारा निरीक्षण की सलाह। यह प्रोटोटाइप केवल अलर्ट देता है, मशीन पर कोई नियंत्रण आदेश नहीं भेजता।"}


def evaluate(readings, now=None):
    """readings: list of dicts with ts (datetime), ascending. Returns alert dicts."""
    now = now or datetime.now()
    if not readings:
        return []
    alerts = []
    last = readings[-1]
    if now - last["ts"] > timedelta(seconds=HEARTBEAT_TIMEOUT_S):
        alerts.append(_R("I04", "high", f"No data from {DEVICE} for over {HEARTBEAT_TIMEOUT_S} seconds (heartbeat missing).",
                         f"{DEVICE} से {HEARTBEAT_TIMEOUT_S} सेकंड से ज़्यादा समय से डेटा नहीं (हार्टबीट गायब)।",
                         f"last seen {last['ts'].strftime('%H:%M:%S')}"))
    labels = {"temp_c": ("Temperature", "तापमान"), "vibration_mm_s": ("Vibration", "कंपन"), "current_a": ("Current", "करंट")}
    for key, (lo, hi_) in RANGES.items():
        v = last[key]
        en_l, hi_l = labels[key]
        if v > hi_ or v < lo:
            alerts.append(_R("I01", "high", f"{en_l} {v} is outside the configured range {lo}-{hi_}.",
                             f"{hi_l} {v} तय सीमा {lo}-{hi_} से बाहर है।", f"{key}={v}"))
        elif v >= WARN[key]:
            alerts.append(_R("I01", "medium", f"{en_l} {v} is near the upper limit ({hi_}).",
                             f"{hi_l} {v} ऊपरी सीमा ({hi_}) के पास है।", f"{key}={v}"))
    if len(readings) >= 2 and abs(readings[-1]["temp_c"] - readings[-2]["temp_c"]) >= JUMP_TEMP:
        alerts.append(_R("I02", "medium", f"Temperature changed by {abs(readings[-1]['temp_c'] - readings[-2]['temp_c']):.1f} degrees in one step.",
                         "तापमान एक कदम में अचानक बदला।", f"delta>={JUMP_TEMP}"))
    if len(readings) >= 3 and all(r["temp_c"] > RANGES["temp_c"][1] for r in readings[-3:]):
        alerts.append(_R("I03", "high", "Temperature stayed above the limit for 3 consecutive readings.",
                         "तापमान लगातार 3 रीडिंग तक सीमा से ऊपर रहा।", "3 consecutive"))
    return alerts
