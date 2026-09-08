import os
from datetime import datetime, timezone
from database.db import one, execute

# Configurable via environment variable, comma-separated
_default_verifiers = "Bob,Charlie"
AUTHORIZED_VERIFIERS = set(
    v.strip()
    for v in os.environ.get("QDS_AUTHORIZED_VERIFIERS", _default_verifiers).split(",")
    if v.strip()
)


def verify_signature(session_id, verifier):
    """
    Verify a quantum-inspired digital signature.

    Checks:
    1. Session exists (anti-forgery)
    2. Verifier is authorized (role-based access)
    3. Session hasn't been consumed (anti-replay)
    4. Measurement quality above threshold (channel integrity)
    """
    row = one("SELECT * FROM signatures WHERE session_id=?", (session_id,))
    now = datetime.now(timezone.utc).isoformat()

    if not row:
        return {
            "ok": False,
            "decision": "REJECT",
            "category": "FORGERY",
            "threat_score": 95,
            "reason": "Unknown session/signature — possible forgery attempt.",
        }

    if verifier not in AUTHORIZED_VERIFIERS:
        execute(
            "INSERT INTO events(session_id,category,actor,decision,threat_score,details,created_at) VALUES(?,?,?,?,?,?,?)",
            (
                session_id,
                "UNAUTHORIZED_VERIFICATION",
                verifier,
                "REJECT",
                90,
                f"Verifier '{verifier}' is not in the authorized list ({', '.join(sorted(AUTHORIZED_VERIFIERS))}).",
                now,
            ),
        )
        return {
            "ok": True,
            "decision": "REJECT",
            "category": "UNAUTHORIZED_VERIFICATION",
            "threat_score": 90,
            "reason": f"Verifier '{verifier}' is not authorized. Only {', '.join(sorted(AUTHORIZED_VERIFIERS))} may verify.",
        }

    if row["consumed"]:
        execute(
            "INSERT INTO events(session_id,category,actor,decision,threat_score,details,created_at) VALUES(?,?,?,?,?,?,?)",
            (
                session_id,
                "REPLAY",
                verifier,
                "REJECT",
                96,
                "Signature/session already consumed — replay attack detected.",
                now,
            ),
        )
        return {
            "ok": True,
            "decision": "REJECT",
            "category": "REPLAY",
            "threat_score": 96,
            "reason": "Replay attack: this session has already been used.",
        }

    if row["measurement_match"] < 80:
        execute(
            "INSERT INTO events(session_id,category,actor,decision,threat_score,details,created_at) VALUES(?,?,?,?,?,?,?)",
            (
                session_id,
                "CHANNEL_MANIPULATION",
                verifier,
                "REJECT",
                85,
                f"Measurement match {row['measurement_match']}% is below the 80% threshold.",
                now,
            ),
        )
        return {
            "ok": True,
            "decision": "REJECT",
            "category": "CHANNEL_MANIPULATION",
            "threat_score": 85,
            "reason": f"Measurement consistency ({row['measurement_match']}%) is below the required 80% threshold.",
        }

    # All checks passed — accept and consume the signature
    execute(
        "UPDATE signatures SET consumed=1,status='VERIFIED' WHERE session_id=?",
        (session_id,),
    )
    execute(
        "INSERT INTO events(session_id,category,actor,decision,threat_score,details,created_at) VALUES(?,?,?,?,?,?,?)",
        (
            session_id,
            "LEGITIMATE",
            verifier,
            "ACCEPT",
            2,
            f"All protocol checks passed. Verified by {verifier}.",
            now,
        ),
    )
    return {
        "ok": True,
        "decision": "ACCEPT",
        "category": "LEGITIMATE",
        "threat_score": 2,
        "measurement_match": row["measurement_match"],
        "reason": "Signature verified successfully. All quantum protocol checks passed.",
    }
