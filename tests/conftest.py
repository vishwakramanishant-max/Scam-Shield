import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session", autouse=True)
def _samples():
    import make_samples
    make_samples.main()


@pytest.fixture()
def tmp_scan(tmp_path, monkeypatch):
    """A throw-away copy of the scan target so tests that apply fixes never touch the shipped samples."""
    dst = tmp_path / "scan_target"
    shutil.copytree(ROOT / "sample_data" / "scan_target", dst)
    monkeypatch.setenv("SCAM_SHIELD_SCAN_ROOTS", str(dst))
    return dst


@pytest.fixture()
def client(tmp_path, tmp_scan):
    import app as appmod
    a = appmod.create_app(tmp_path / "inst")
    log = tmp_path / "auth.log"
    log.write_text((ROOT / "sample_data" / "auth_sample.log").read_text())
    a.config["SAMPLE_LOG"] = str(log)
    c = a.test_client()
    c.post("/setup", data={"username": "owner", "password": "correct-horse-9", "csrf_token": _tok(c, "/setup")})
    c.post("/login", data={"username": "owner", "password": "correct-horse-9", "csrf_token": _tok(c, "/login")})
    c.csrf = _tok(c, "/")
    return c


def _tok(c, path):
    import re
    html = c.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([0-9a-f]+)"', html) or re.search(r'name="csrf" content="([0-9a-f]+)"', html)
    if not m:
        m = re.search(r'content="([0-9a-f]{32})"', html)
    return m.group(1)
