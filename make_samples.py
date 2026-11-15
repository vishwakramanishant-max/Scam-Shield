"""Generate ALL demo data. Everything is synthetic: dummy QR codes, fake keys, made-up transactions,
generated log lines and a harmless fake APK (a ZIP with text). No real credentials or devices are involved."""
import io
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import qrcode

BASE = Path(__file__).resolve().parent / "sample_data"
SHOP_UPI = "sharmageneral@okaxis"
SHOP_NAME = "Sharma General Store"


def qr_png(text, path):
    img = qrcode.make(text, box_size=8, border=4)
    img.save(path)


DEMO_SALES = [(198, 250.00), (195, 1200.00), (88, 80.00), (58, 450.00), (30, 999.00)]


def statement_csv(now):
    def t(m):
        return (now - timedelta(minutes=m)).strftime("%Y-%m-%d %H:%M:%S")
    return ("txn_id,timestamp,amount,status,reference\n"
            f"T1001,{t(199)},250.00,SUCCESS,\n"
            f"T1002,{t(194)},1200.00,SUCCESS,\n"
            f"T1003,{t(87)},80.00,SUCCESS,\n"
            f"T1003,{t(87)},80.00,SUCCESS,\n"                       # duplicate row
            f"T1004,{t(57)},450.00,PENDING,\n"                      # pending
            f"T1005,{t(40)},-100.00,REFUND,\n"                      # refund
            "bad_row_without_fields\n")                            # malformed -> rejected


def main(now=None):
    now = now or datetime.now().replace(second=0, microsecond=0)
    BASE.mkdir(exist_ok=True)
    qdir = BASE / "qr"
    qdir.mkdir(exist_ok=True)
    qr_png(f"upi://pay?pa={SHOP_UPI}&pn={SHOP_NAME.replace(' ', '%20')}&cu=INR", qdir / "01_genuine_shop_qr.png")
    qr_png("upi://pay?pa=sharmagenera1@okaxis&pn=Sharma%20General%20Store&cu=INR", qdir / "02_lookalike_swapped_qr.png")
    qr_png("upi://pay?pa=quickcash772@ybl&pn=Quick%20Cash&cu=INR", qdir / "03_different_payee_qr.png")
    qr_png("https://bit.ly/3xPayNow", qdir / "04_shortened_link_qr.png")
    qr_png(f"upi://pay?pa={SHOP_UPI}&pn=Raju%20Traders&cu=INR", qdir / "05_name_differs_qr.png")

    # statements: ts relative to 'now' so the demo always lines up
    def t(m):
        return (now - timedelta(minutes=m)).strftime("%Y-%m-%d %H:%M:%S")
    (BASE / "statement_good.csv").write_text(statement_csv(now))
    (BASE / "statement_bad_columns.csv").write_text("id,when,value\n1,2026-01-01,100\n")
    (BASE / "demo_sales.csv").write_text(
        "minutes_ago,amount,ref\n"
        "198,250.00,\n195,1200.00,\n88,80.00,\n58,450.00,\n30,999.00,\n")

    # scan target with planted FAKE secrets
    sd = BASE / "scan_target"
    sd.mkdir(exist_ok=True)
    (sd / "billing_app.py").write_text(
        'import sqlite3\n\n'
        'DB_PASSWORD = "Rj9#kL2mQ8vXz4Tn"\n'
        'API_KEY = os.environ.get("API_KEY")\n'
        'PAYMENT_TOKEN = "d93Kx0LpQm72VnB8sWe5"\n\n'
        'def find_customer(conn, name):\n'
        '    return conn.execute("SELECT * FROM customers WHERE name = \'%s\'" % name)\n\n'
        'def fetch(url):\n'
        '    import requests\n'
        '    return requests.get(url, verify=False)\n')
    (sd / "deploy.env").write_text(
        "AWS_KEY=AKIAQ7XK2MZP4WNB5TDE\nDB_URL=postgres://shopadmin:pX7mK2vL9qZ@10.0.0.5:5432/billing\n"
        "SECRET_KEY=changeme\n")
    (sd / "notes.txt").write_text("Ordinary notes: the password reset flow sends an email.\ntoken = <your-token-here>\n")

    # synthetic auth log
    base = now - timedelta(minutes=30)
    lines = []
    for i in range(7):
        ts = base + timedelta(seconds=i * 7)
        lines.append(f"{ts.strftime('%b %e %H:%M:%S')} shopbox sshd[1822]: Failed password for admin from 203.0.113.45 port {40010+i} ssh2")
    ts = base + timedelta(minutes=12)
    lines.append(f"{ts.strftime('%b %e %H:%M:%S')} shopbox sshd[1901]: Failed password for shopkeeper from 192.0.2.10 port 43000 ssh2")
    lines.append(f"{(ts + timedelta(seconds=20)).strftime('%b %e %H:%M:%S')} shopbox sshd[1901]: Accepted password for shopkeeper from 192.0.2.10 port 43001 ssh2")
    (BASE / "auth_sample.log").write_text("\n".join(lines) + "\n")

    # harmless fake APK: a ZIP holding a text 'manifest' that merely contains permission names
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", "<manifest> android.permission.READ_SMS android.permission.RECEIVE_SMS "
                                          "android.permission.BIND_ACCESSIBILITY_SERVICE android.permission.INTERNET </manifest>")
        z.writestr("classes.dex", "not real code")
    (BASE / "SBI_KYC_Update_FAKE_SAMPLE.apk").write_bytes(buf.getvalue())
    print("sample data written to", BASE)


if __name__ == "__main__":
    main()
