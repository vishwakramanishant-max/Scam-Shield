"""Background worker: makes the shield AUTOMATIC. Runs the Linux folder scan and the failed-login check on a schedule
and writes alerts into the same database the dashboard reads.

    python worker.py              # loop every 60 s
    python worker.py --once       # single pass (good for cron / tests)

Run it as a normal user, never root. See docs/scam-shield-worker.service for a systemd unit."""
import argparse
import time

import config
import db
import runners


def one_pass(instance=None):
    inst = instance or config.instance_dir()
    inst.mkdir(parents=True, exist_ok=True)
    path = inst / "shield.db"
    db.init(path)
    conn = db.connect(path)
    try:
        s = runners.run_secret_scan(conn)
        l = runners.run_login_monitor(conn, str(config.SAMPLE / "auth_sample.log"))
        print(time.strftime("%H:%M:%S"), "secret scan:", len(s.get("findings", [])), "findings |",
              "login monitor:", l["status"], len(l["findings"]), "pattern(s)")
    finally:
        conn.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=int, default=60)
    a = ap.parse_args()
    while True:
        one_pass()
        if a.once:
            break
        time.sleep(a.interval)
