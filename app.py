import os
import time
import hashlib
import secrets
from functools import wraps
from collections import defaultdict
from flask import Flask, render_template, request, jsonify, g

from database.db import init_db, get_metrics, list_events
from security.signature import generate_signature
from security.verification import verify_signature
from security.threat_detection import simulate_attack

app = Flask(__name__)

# Security: Use a random secret key (not hardcoded)
app.config["SECRET_KEY"] = os.environ.get("QDS_SECRET_KEY", secrets.token_hex(32))

# Initialize the database
init_db()

# ─── Rate Limiting (in-memory, per-IP) ───────────────────────────────
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 30  # max requests per window per IP
_rate_store = defaultdict(list)


def check_rate_limit():
    """Simple in-memory rate limiter. Returns True if request is allowed."""
    ip = request.remote_addr or "unknown"
    now = time.time()
    # Clean old entries
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_store[ip]) >= RATE_LIMIT_MAX:
        return False
    _rate_store[ip].append(now)
    return True


# ─── Security Headers ────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    """Add security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
    )
    return response


# ─── Input Validation Helpers ─────────────────────────────────────────
MAX_MESSAGE_LEN = 2000
MAX_FIELD_LEN = 100


def validate_field(value, name, max_len=MAX_FIELD_LEN):
    """Validate a string field: not empty, within length limits."""
    if not value:
        return None, f"{name} is required."
    if len(value) > max_len:
        return None, f"{name} must be {max_len} characters or fewer."
    return value, None


# ─── Page Routes ──────────────────────────────────────────────────────
@app.get("/")
def home():
    return render_template("index.html")


# ─── API Routes ───────────────────────────────────────────────────────
@app.post("/api/generate")
def api_generate():
    if not check_rate_limit():
        return jsonify({"ok": False, "error": "Rate limit exceeded. Try again later."}), 429

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400

    message, err = validate_field(data.get("message", "").strip(), "Message", MAX_MESSAGE_LEN)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    signer, err = validate_field(data.get("signer", "").strip(), "Signer")
    if err:
        return jsonify({"ok": False, "error": err}), 400

    try:
        result = generate_signature(message, signer)
        return jsonify({"ok": True, "signature": result})
    except Exception as e:
        return jsonify({"ok": False, "error": "Internal error during signature generation."}), 500


@app.post("/api/verify")
def api_verify():
    if not check_rate_limit():
        return jsonify({"ok": False, "error": "Rate limit exceeded. Try again later."}), 429

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400

    session_id, err = validate_field(data.get("session_id", "").strip(), "Session ID")
    if err:
        return jsonify({"ok": False, "error": err}), 400

    verifier, err = validate_field(data.get("verifier", "").strip(), "Verifier")
    if err:
        return jsonify({"ok": False, "error": err}), 400

    try:
        result = verify_signature(session_id, verifier)
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": "Internal error during verification."}), 500


@app.post("/api/attack")
def api_attack():
    if not check_rate_limit():
        return jsonify({"ok": False, "error": "Rate limit exceeded. Try again later."}), 429

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400

    attack_type, err = validate_field(data.get("attack_type", "").strip(), "Attack type")
    if err:
        return jsonify({"ok": False, "error": err}), 400

    session_id, err = validate_field(data.get("session_id", "").strip(), "Session ID")
    if err:
        return jsonify({"ok": False, "error": err}), 400

    attacker = data.get("attacker", "Mallory").strip() or "Mallory"
    if len(attacker) > MAX_FIELD_LEN:
        return jsonify({"ok": False, "error": f"Attacker name must be {MAX_FIELD_LEN} characters or fewer."}), 400

    try:
        return jsonify(simulate_attack(session_id, attack_type, attacker))
    except Exception as e:
        return jsonify({"ok": False, "error": "Internal error during attack simulation."}), 500


@app.get("/api/dashboard")
def api_dashboard():
    try:
        return jsonify({"metrics": get_metrics(), "events": list_events(20)})
    except Exception as e:
        return jsonify({"ok": False, "error": "Failed to load dashboard data."}), 500


# ─── Entry Point ──────────────────────────────────────────────────────
if __name__ == "__main__":
    # debug=False for security; set QDS_DEBUG=1 to enable during development
    debug_mode = os.environ.get("QDS_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)
