import os
import json
import hmac
import base64
import hashlib

from flask import (
    Flask,
    request,
    redirect,
    make_response,
    render_template,
    url_for,
)

app = Flask(__name__)

# --- Config (loaded from the environment; do NOT hardcode in source shipped to players) ---
SECRET = os.environ.get("JWT_SECRET", "dev-only-secret-change-me").encode()
FLAG = os.environ.get("FLAG", "FLAG{local_dev_flag}")
COOKIE_NAME = "token"


# ---------------------------------------------------------------------------
# Minimal JWT implementation (INTENTIONALLY supports alg=none as the challenge bug).
# ---------------------------------------------------------------------------
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def jwt_encode(payload: dict) -> str:
    """Sign a valid token with HS256 (used on a real user login)."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(SECRET, signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def jwt_decode(token: str):
    """Verify a token. Return the payload if valid, otherwise None."""
    parts = token.split(".")
    if len(parts) == 2:
        header_b64, payload_b64 = parts
        signature_b64 = ""
    elif len(parts) == 3:
        header_b64, payload_b64, signature_b64 = parts
    else:
        return None

    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        return None

    alg = header.get("alg", "")

    # >>> VULNERABILITY <<<
    # The server trusts a token that declares "alg": "none" and SKIPS signature checking.
    # An attacker only needs to craft a token with alg=none and role=admin.
    if alg == "none":
        return payload

    if alg == "HS256":
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected = _b64url_encode(hmac.new(SECRET, signing_input, hashlib.sha256).digest())
        if hmac.compare_digest(expected, signature_b64):
            return payload
        return None

    # Any other algorithm -> reject.
    return None


def current_user():
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    return jwt_decode(token)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("home"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == "guest" and password == "guest":
        token = jwt_encode({"user": "guest", "role": "user"})
        resp = make_response(redirect(url_for("home")))
        resp.set_cookie(COOKIE_NAME, token, httponly=False, samesite="Lax")
        return resp
    return render_template("login.html", error="Invalid username or password."), 401


@app.route("/home")
def home():
    user = current_user()
    if not user:
        return redirect(url_for("index"))
    return render_template("home.html", user=user)


@app.route("/admin")
def admin():
    user = current_user()
    if not user:
        return redirect(url_for("index"))
    if user.get("role") == "admin":
        return render_template("admin.html", user=user, flag=FLAG)
    return render_template("admin.html", user=user, flag=None), 403


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie(COOKIE_NAME)
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3642)
