import os
import time
import hashlib
import secrets
from functools import wraps
from collections import defaultdict
from flask import Flask, render_template, request, jsonify, g

from database.db import init_db, get_metrics, list_events, one
from security.signature import generate_signature
from security.verification import verify_signature
from security.threat_detection import simulate_attack, get_attack_knowledge

app = Flask(__name__)

# Security: Use a random secret key (not hardcoded)
app.config["SECRET_KEY"] = os.environ.get("QDS_SECRET_KEY", secrets.token_hex(32))

# Initialize the database
init_db()

# ─── Rate Limiting (in-memory, per-IP) ───────────────────────────────
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 60  # max requests per window per remote IP
RATE_LIMIT_LOCAL_MAX = 300  # generous ceiling for localhost to accommodate polling
_rate_store = defaultdict(list)


def check_rate_limit():
    """Simple in-memory rate limiter. Returns True if request is allowed."""
    ip = request.remote_addr or "unknown"
    now = time.time()
    # Clean old entries
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_LIMIT_WINDOW]
    limit = RATE_LIMIT_LOCAL_MAX if ip in ("127.0.0.1", "::1", "localhost", "unknown") else RATE_LIMIT_MAX
    if len(_rate_store[ip]) >= limit:
        return False
    _rate_store[ip].append(now)
    return True


# ─── Security & CORS Headers ─────────────────────────────────────────
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        res = jsonify({"ok": True})
        res.headers["Access-Control-Allow-Origin"] = "*"
        res.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        res.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return res


@app.after_request
def add_security_headers(response):
    """Add security and CORS headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' http://127.0.0.1:* http://localhost:*; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self' http://127.0.0.1:* http://localhost:*; "
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


@app.get("/api/signature/<session_id>")
def api_signature_details(session_id):
    """Fetch full details of a quantum signature by session ID (for the inspector panel)."""
    if not check_rate_limit():
        return jsonify({"ok": False, "error": "Rate limit exceeded. Try again later."}), 429

    session_id = session_id.strip()
    if not session_id or len(session_id) > MAX_FIELD_LEN:
        return jsonify({"ok": False, "error": "Invalid session ID."}), 400

    try:
        row = one("SELECT * FROM signatures WHERE session_id=?", (session_id,))
        if not row:
            return jsonify({"ok": False, "error": "Session not found."})

        sig_dict = {
            "session_id": row["session_id"],
            "message": row["message"],
            "message_hash": row["message_hash"],
            "signer": row["signer"],
            "bell_state": row["bell_state"],
            "pauli_correction": row["pauli_correction"],
            "measurement_match": row["measurement_match"],
            "status": row["status"],
            "created_at": row["created_at"],
            "consumed": bool(row["consumed"]),
        }
        if "circuit_diagram" in row.keys():
            sig_dict["circuit_diagram"] = row["circuit_diagram"]
        if "backend" in row.keys():
            sig_dict["backend"] = row["backend"]

        return jsonify({
            "ok": True,
            "signature": sig_dict,
        })
    except Exception:
        return jsonify({"ok": False, "error": "Internal error fetching signature details."}), 500


@app.get("/api/quantum-status")
def api_quantum_status():
    """Return status and telemetry of the quantum computing stack."""
    try:
        import qiskit
        import qiskit_aer
        import pennylane as qml

        return jsonify({
            "ok": True,
            "qiskit_version": qiskit.__version__,
            "aer_version": qiskit_aer.__version__,
            "pennylane_version": qml.__version__,
            "simulator": "AerSimulator (statevector)",
            "pennylane_device": "default.qubit (4 wires)",
            "teleportation_protocol": "3-Qubit Bennett Teleportation with Bell Basis Measurement",
            "qnn_architecture": "4-Qubit Variational Quantum Classifier (AngleEmbedding + StronglyEntanglingLayers)",
            "status": "ACTIVE",
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.get("/api/attack-info")
def api_attack_info():
    """Return the full attack knowledge base for the educational explainer UI."""
    try:
        knowledge = get_attack_knowledge()
        return jsonify({"ok": True, "attacks": knowledge})
    except Exception:
        return jsonify({"ok": False, "error": "Failed to load attack knowledge base."}), 500


@app.post("/api/rehash")
def api_rehash():
    """Compute an iterative SHA-256 hash chain: text → hash₁ → hash₂ → ... → hashₙ."""
    if not check_rate_limit():
        return jsonify({"ok": False, "error": "Rate limit exceeded. Try again later."}), 429

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400

    text, err = validate_field(data.get("text", "").strip(), "Text", MAX_MESSAGE_LEN)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    rounds = data.get("rounds", 3)
    if not isinstance(rounds, int) or rounds < 1 or rounds > 20:
        return jsonify({"ok": False, "error": "Rounds must be an integer between 1 and 20."}), 400

    try:
        chain = []
        current = text
        for i in range(rounds):
            hashed = hashlib.sha256(current.encode()).hexdigest()
            chain.append({
                "round": i + 1,
                "input": current if i == 0 else f"{current[:16]}...{current[-16:]}",
                "input_full": current,
                "output": hashed,
            })
            current = hashed

        return jsonify({
            "ok": True,
            "original_text": text,
            "rounds": rounds,
            "final_hash": current,
            "chain": chain,
        })
    except Exception:
        return jsonify({"ok": False, "error": "Internal error during rehashing."}), 500


@app.get("/api/dashboard")
def api_dashboard():
    try:
        return jsonify({"metrics": get_metrics(), "events": list_events(20)})
    except Exception as e:
        app.logger.error(f"Dashboard error: {e}")
        return jsonify({"ok": False, "error": "Failed to load dashboard data."}), 500


# ─── Global Error Handlers (Guaranteed CORS on Error) ─────────────────
@app.errorhandler(404)
def handle_404(e):
    return jsonify({"ok": False, "error": "Endpoint not found."}), 404


@app.errorhandler(429)
def handle_429(e):
    return jsonify({"ok": False, "error": "Rate limit exceeded. Try again in a few moments."}), 429


@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled server exception: {e}", exc_info=True)
    return jsonify({"ok": False, "error": "Internal server error."}), 500


# ─── Entry Point ──────────────────────────────────────────────────────
if __name__ == "__main__":
    debug_mode = os.environ.get("QDS_DEBUG", "0") == "1"
    host = os.environ.get("QDS_HOST", "127.0.0.1")
    port = int(os.environ.get("QDS_PORT", 5000))
    print(f"\n========================================================")
    print(f" Quantum Cyber Threat Detection API Server")
    print(f" Access UI & API at: http://{host}:{port}")
    print(f"========================================================\n")
    app.run(debug=debug_mode, host=host, port=port)

