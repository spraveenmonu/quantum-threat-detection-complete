import numpy as np
from qiskit.quantum_info import Pauli, Operator
import pennylane as qml

CORRECTIONS = {
    "00": "I",
    "01": "X",
    "10": "Z",
    "11": "XZ"
}


def correction_for_bits(bits: str) -> str:
    """Return Pauli correction symbol ('I', 'X', 'Z', 'XZ') for Bell measurement bits."""
    return CORRECTIONS.get(str(bits).strip(), "I")


def get_qiskit_pauli(correction: str) -> Operator:
    """Return Qiskit Operator for the Pauli correction."""
    if correction == "I":
        return Operator(Pauli("I"))
    elif correction == "X":
        return Operator(Pauli("X"))
    elif correction == "Z":
        return Operator(Pauli("Z"))
    elif correction in ("XZ", "ZX"):
        # Z * X
        return Operator(Pauli("Z")) @ Operator(Pauli("X"))
    return Operator(Pauli("I"))


def get_pennylane_pauli(correction: str, wire: int = 0):
    """Return corresponding PennyLane operation for wire."""
    if correction == "I":
        return qml.Identity(wires=wire)
    elif correction == "X":
        return qml.PauliX(wires=wire)
    elif correction == "Z":
        return qml.PauliZ(wires=wire)
    elif correction in ("XZ", "ZX"):
        return [qml.PauliX(wires=wire), qml.PauliZ(wires=wire)]
    return qml.Identity(wires=wire)


def apply_pauli_correction_circuit(qc, correction: str, target_qubit: int):
    """Apply conditional Pauli gate correction onto target qubit in a Qiskit circuit."""
    if correction == "X":
        qc.x(target_qubit)
    elif correction == "Z":
        qc.z(target_qubit)
    elif correction in ("XZ", "ZX"):
        qc.x(target_qubit)
        qc.z(target_qubit)
    # If "I", do nothing
