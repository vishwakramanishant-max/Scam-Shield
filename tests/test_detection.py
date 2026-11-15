from services import upi_risk, url_risk
from tests.dataset import MESSAGES, URLS


def flagged(res):
    return res["level"] in ("Medium", "High")


def test_pin_to_receive_is_high():
    r = upi_risk.analyze("Refund pending. Enter your UPI PIN to receive the money now")
    assert r["level"] == "High" and any(x["id"] == "U01" for x in r["reasons"])


def test_negated_warning_is_not_flagged():
    for t in ("Never share your UPI PIN or OTP with anyone.", "Your OTP is 123456. Do not share it with anyone."):
        assert upi_risk.analyze(t)["level"] == "Low"


def test_every_reason_has_both_languages_and_rule_id():
    r = upi_risk.analyze("KYC is pending, account will be blocked. Click http://sbi-kyc.xyz and enter UPI PIN to receive refund immediately")
    assert r["reasons"]
    for x in r["reasons"]:
        assert x["id"] and x["en"] and x["hi"]
    assert r["next_en"] and r["next_hi"]


def test_unparseable_input_is_unknown_not_safe():
    for t in ("", "  ", "??", "12"):
        assert upi_risk.analyze(t)["level"] == "Unknown"


def test_low_wording_never_says_safe():
    r = upi_risk.analyze("Your electricity bill is due on the 20th")
    assert "not a guarantee" in r["next_en"].lower()


def test_very_long_input_is_bounded():
    r = upi_risk.analyze("urgent " * 5000)
    assert r["level"] in ("Low", "Medium", "High")


def test_url_edge_cases():
    assert url_risk.analyze("")["level"] == "Unknown"
    assert url_risk.analyze("not a url at all")["level"] == "Unknown"
    assert url_risk.analyze("http://")["level"] == "Unknown"
    assert url_risk.analyze("https://" + "a" * 3000 + ".com")["level"] == "Unknown"


def test_url_never_fetches(monkeypatch):
    import socket
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", boom)
    url_risk.analyze("http://paytm-kyc.xyz")           # must not touch the network
    upi_risk.analyze("see http://paytm-kyc.xyz now")


def test_labelled_message_set_meets_release_gate():
    tp = fp = fn = tn = 0
    for text, is_scam, _ in MESSAGES:
        f = flagged(upi_risk.analyze(text))
        tp += f and is_scam; fp += f and not is_scam; fn += (not f) and is_scam; tn += (not f) and not is_scam
    precision, recall = tp / (tp + fp), tp / (tp + fn)
    fpr = fp / (fp + tn)
    assert recall >= 0.85, (tp, fn)
    assert precision >= 0.85, (tp, fp)
    assert fpr <= 0.10, (fp, tn)


def test_labelled_url_set_meets_release_gate():
    tp = fp = fn = tn = 0
    for u, bad, _ in URLS:
        f = flagged(url_risk.analyze(u))
        tp += f and bad; fp += f and not bad; fn += (not f) and bad; tn += (not f) and not bad
    assert tp / (tp + fn) >= 0.9 and fp / (fp + tn) <= 0.05, (tp, fn, fp, tn)
