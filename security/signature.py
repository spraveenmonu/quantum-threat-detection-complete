import hashlib, uuid
from datetime import datetime, timezone
from database.db import execute
from quantum.bell_state import default_bell_state
from quantum.teleportation import simulate_teleportation

def generate_signature(message, signer):
    session_id = "QDS-" + uuid.uuid4().hex[:8].upper()
    message_hash = hashlib.sha256(message.encode()).hexdigest()
    q = simulate_teleportation()
    created = datetime.now(timezone.utc).isoformat()
    execute("""INSERT INTO signatures
        (session_id,message,message_hash,signer,bell_state,pauli_correction,measurement_match,status,created_at,consumed)
        VALUES (?,?,?,?,?,?,?,?,?,0)""",
        (session_id,message,message_hash,signer,default_bell_state(),
         q["pauli_correction"],q["measurement_match"],"GENERATED",created))
    return {
        "session_id": session_id, "message_hash": message_hash, "signer": signer,
        "bell_state": default_bell_state(), "bell_measurement": q["bell_measurement"],
        "pauli_correction": q["pauli_correction"], "measurement_match": q["measurement_match"],
        "status": "GENERATED", "created_at": created
    }
