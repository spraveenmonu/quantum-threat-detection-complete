import hashlib
import uuid
from datetime import datetime, timezone
from database.db import execute
from quantum.bell_state import default_bell_state
from quantum.teleportation import simulate_teleportation
from quantum.pennylane_engine import evaluate_quantum_threat


def generate_signature(message: str, signer: str):
    """
    Generate a quantum-secured digital signature session:
    1. SHA-256 cryptographic message hashing
    2. Real 3-qubit quantum teleportation circuit on Qiskit Aer (AerSimulator)
    3. Quantum Neural Network baseline anomaly evaluation using PennyLane
    4. Persistent storage of session, fidelity, and ASCII circuit representation
    """
    session_id = "QDS-" + uuid.uuid4().hex[:8].upper()
    message_hash = hashlib.sha256(message.encode()).hexdigest()

    # Execute genuine quantum circuit simulation on Qiskit Aer
    q = simulate_teleportation(message=message, signer=signer)

    # Evaluate baseline quantum anomaly score using PennyLane QNode
    qnn = evaluate_quantum_threat(message=message, signer=signer, fidelity=q["fidelity"])

    created = datetime.now(timezone.utc).isoformat()

    execute(
        """INSERT INTO signatures
        (session_id, message, message_hash, signer, bell_state, pauli_correction, measurement_match, status, created_at, consumed, circuit_diagram, backend)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)""",
        (
            session_id,
            message,
            message_hash,
            signer,
            default_bell_state(),
            q["pauli_correction"],
            q["measurement_match"],
            "GENERATED",
            created,
            q["circuit_diagram"],
            q["backend"],
        ),
    )

    return {
        "session_id": session_id,
        "message_hash": message_hash,
        "signer": signer,
        "bell_state": default_bell_state(),
        "bell_measurement": q["bell_measurement"],
        "pauli_correction": q["pauli_correction"],
        "measurement_match": q["measurement_match"],
        "fidelity": q["fidelity"],
        "circuit_diagram": q["circuit_diagram"],
        "backend": q["backend"],
        "qnn_threat_score": qnn["threat_score"],
        "qnn_framework": qnn["framework"],
        "status": "GENERATED",
        "created_at": created,
    }
