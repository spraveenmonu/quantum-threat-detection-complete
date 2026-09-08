from datetime import datetime, timezone
from database.db import one, execute


def log_event(session_id, category, actor, score, details):
    """Log a security event to the database."""
    execute(
        "INSERT INTO events(session_id,category,actor,decision,threat_score,details,created_at) VALUES(?,?,?,?,?,?,?)",
        (
            session_id,
            category,
            actor,
            "REJECT",
            score,
            details,
            datetime.now(timezone.utc).isoformat(),
        ),
    )


# Attack definitions: type -> (category, score, detail_template)
ATTACK_TYPES = {
    "forgery": {
        "category": "FORGERY",
        "score": 94,
        "detail": "Message/signature binding has been altered. Hash mismatch detected in quantum-signed payload.",
    },
    "impersonation": {
        "category": "IMPERSONATION",
        "score": 92,
        "detail_fn": lambda row, attacker: (
            f"Identity mismatch: expected signer '{row['signer']}' but actor '{attacker}' attempted verification. "
            f"Quantum identity binding violated."
        ),
    },
    "replay": {
        "category": "REPLAY",
        "score": 97,
        "detail": "Session reuse detected. One-time quantum signature protocol violated — replay protection triggered.",
    },
    "unauthorized": {
        "category": "UNAUTHORIZED_VERIFICATION",
        "score": 90,
        "detail_fn": lambda row, attacker: (
            f"Unauthorized actor '{attacker}' attempted verification without proper role credentials."
        ),
    },
    "channel": {
        "category": "CHANNEL_MANIPULATION",
        "score": 88,
        "detail": "Quantum channel manipulation simulated. Measurement consistency degraded below safe threshold, indicating potential eavesdropping.",
    },
}


def simulate_attack(session_id, attack_type, attacker):
    """
    Simulate a cyber attack against a quantum-signed session.

    Supported attack types: forgery, impersonation, replay, unauthorized, channel.
    Each attack type has a predefined threat score and generates a detailed log entry.
    """
    row = one("SELECT * FROM signatures WHERE session_id=?", (session_id,))
    if not row:
        return {"ok": False, "error": "Session not found. Generate a signature first."}

    attack_type = attack_type.lower().strip()
    attack_def = ATTACK_TYPES.get(attack_type)

    if not attack_def:
        valid_types = ", ".join(sorted(ATTACK_TYPES.keys()))
        return {
            "ok": False,
            "error": f"Unknown attack type '{attack_type}'. Valid types: {valid_types}",
        }

    category = attack_def["category"]
    score = attack_def["score"]

    # Build detail string — some attacks use dynamic details based on session/attacker
    if "detail_fn" in attack_def:
        details = attack_def["detail_fn"](row, attacker)
    else:
        details = attack_def["detail"]

    log_event(session_id, category, attacker, score, details)

    return {
        "ok": True,
        "session_id": session_id,
        "attacker": attacker,
        "category": category,
        "decision": "REJECT",
        "threat_score": score,
        "reason": details,
    }
