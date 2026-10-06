from flask import Flask, request, jsonify
from urllib.parse import urlparse
import requests, ssl, socket, time
from safety import safe_get, is_safe_host
from ratelimit import init as init_limit
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
init_limit(app)

HEADERS = {
    "Strict-Transport-Security": "أضف الترويسة: Strict-Transport-Security: max-age=31536000",
    "Content-Security-Policy": "أضف سياسة CSP لتحديد مصادر السكربتات المسموحة",
    "X-Frame-Options": "أضف X-Frame-Options: DENY لمنع تضمين موقعك بإطار",
    "X-Content-Type-Options": "أضف X-Content-Type-Options: nosniff",
}

SENSITIVE = [
    ("/.git/HEAD", "ref:", "مجلد .git غير مكشوف"),
    ("/.env", "=", "ملف .env غير مكشوف"),
]

def cookies_ok(resp):
    cookies = resp.raw.headers.getlist("Set-Cookie")
    for c in cookies:
        parts = [p.strip().lower() for p in c.split(";")]
        if "secure" not in parts or "httponly" not in parts:
            return False
    return True

@app.route("/")
def home():
    return app.send_static_file("index.html")

@app.route("/scan")
def scan():
    raw = request.args.get("url", "").strip()
    if not raw.startswith("http"):
        raw = "https://" + raw
    host = urlparse(raw).hostname
    if not host:
        return jsonify(error="رابط غير صالح"), 400
    if not is_safe_host(host):
        return jsonify(error="هذا العنوان غير مسموح فحصه"), 400
    try:
        r = safe_get("https://" + host, timeout=10)
    except (requests.RequestException, ValueError):
        return jsonify(error="تعذّر الوصول للموقع"), 400

    checks = [{"name": h, "ok": h in r.headers, "fix": fix}
              for h, fix in HEADERS.items()]

    days = None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                exp = ssl.cert_time_to_seconds(ss.getpeercert()["notAfter"])
                days = int((exp - time.time()) / 86400)
    except Exception:
        pass
    cert_ok = days is not None and days > 0
    name = "شهادة HTTPS صالحة"
    if cert_ok:
        name += f" (باقي {days} يوم)"
    checks.append({"name": name, "ok": cert_ok,
                   "fix": "الشهادة منتهية أو غير صالحة، جدّدها (مثلاً Let's Encrypt)"})

    try:
        h = requests.get("http://" + host, timeout=10, allow_redirects=False)
        redir = h.is_redirect and h.headers.get("Location", "").startswith("https://")
    except requests.RequestException:
        redir = False
    checks.append({"name": "تحويل http إلى https", "ok": redir,
                   "fix": "فعّل إعادة توجيه 301 من http إلى https بالسيرفر"})

    for path, sig, label in SENSITIVE:
        try:
            x = requests.get("https://" + host + path, timeout=8, allow_redirects=False)
            body = x.text[:2000]
            exposed = (x.status_code == 200
                       and not body.lstrip().startswith("<")
                       and sig in body)
        except requests.RequestException:
            exposed = False
        checks.append({"name": label, "ok": not exposed,
                       "fix": "الملف مكشوف للعموم! احجبه من إعدادات السيرفر فوراً وغيّر أي مفاتيح أو كلمات سر كانت فيه"})

    checks.append({"name": "الكوكيز محمية (Secure + HttpOnly)", "ok": cookies_ok(r),
                   "fix": "أضف الخاصيتين Secure وHttpOnly لكل كوكي يضبطه موقعك"})

    score = int(sum(c["ok"] for c in checks) / len(checks) * 100)
    return jsonify(url=raw, score=score, checks=checks)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
