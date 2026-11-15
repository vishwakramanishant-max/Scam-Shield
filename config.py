import os
import secrets
from pathlib import Path

BASE = Path(__file__).resolve().parent
SAMPLE = BASE / "sample_data"


def instance_dir():
    return Path(os.environ.get("SCAM_SHIELD_INSTANCE", BASE / "instance"))


def allowed_scan_roots():
    roots = [SAMPLE / "scan_target"]
    extra = os.environ.get("SCAM_SHIELD_SCAN_ROOTS", "")
    roots += [Path(p) for p in extra.split(os.pathsep) if p.strip()]
    return roots


def load_secret_key(inst: Path):
    inst.mkdir(parents=True, exist_ok=True)
    kf = inst / "secret_key"
    if not kf.exists():
        kf.write_text(secrets.token_hex(32))
        os.chmod(kf, 0o600)
    return kf.read_text().strip()


REAL_AUTH_LOG = os.environ.get("SCAM_SHIELD_AUTH_LOG", "/var/log/auth.log")
MAX_UPLOAD = 12 * 1024 * 1024
