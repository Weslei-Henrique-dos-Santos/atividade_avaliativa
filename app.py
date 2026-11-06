import os, time, secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort
from werkzeug.security import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],          # nunca no código
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=1800,
)
USER = os.environ["APP_USER"]
PW_HASH = os.environ["APP_PASSWORD_HASH"]
DUMMY = "scrypt:32768:8:1$x$" + "0" * 128
fails = {}  # ip -> [contagem, início da janela]

def csrf_token():
    session.setdefault("csrf", secrets.token_hex(16))
    return session["csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

def check_csrf():
    if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
        abort(400)

def login_required(f):  # A01
    @wraps(f)
    def w(*a, **k):
        if not session.get("auth"):
            return redirect(url_for("login"))
        return f(*a, **k)
    return w

@app.after_request
def headers(r):  # A02
    r.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Cache-Control"] = "no-store"
    r.headers["Strict-Transport-Security"] = "max-age=31536000"
    return r

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        check_csrf()
        ip, now = request.remote_addr, time.time()
        cnt, start = fails.get(ip, [0, now])
        if now - start > 300:
            cnt, start = 0, now
        if cnt >= 5:  # A07: limite de tentativas
            return render_template("login.html", error="Muitas tentativas. Aguarde."), 429
        u = request.form.get("username", "")[:64]
        p = request.form.get("password", "")[:128]
        ok = check_password_hash(PW_HASH, p) and secrets.compare_digest(u, USER)
        if ok:
            fails.pop(ip, None)
            session.clear()  # evita session fixation
            session.permanent = True
            session["auth"] = True
            return redirect(url_for("dashboard"))
        fails[ip] = [cnt + 1, start]
        error = "Usuário ou senha inválidos."  # mensagem genérica
    return render_template("login.html", error=error), (401 if error else 200)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=USER)

@app.route("/logout", methods=["POST"])
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login"))
