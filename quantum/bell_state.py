import numpy as np
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

BELL_STATES = ["|Φ+⟩", "|Φ−⟩", "|Ψ+⟩", "|Ψ−⟩"]


def default_bell_state():
    return "|Φ+⟩"


def create_bell_circuit(bell_type="|Φ+⟩") -> QuantumCircuit:
    """
    Construct a 2-qubit Qiskit QuantumCircuit that prepares the requested Bell state.
    |Φ+⟩ = (|00⟩ + |11⟩) / √2
    |Φ−⟩ = (|00⟩ - |11⟩) / √2
    |Ψ+⟩ = (|01⟩ + |10⟩) / √2
    |Ψ−⟩ = (|01⟩ - |10⟩) / √2
    """
    qc = QuantumCircuit(2, name=f"Bell_{bell_type}")

    if bell_type == "|Φ+⟩":
        qc.h(0)
        qc.cx(0, 1)
    elif bell_type in ("|Φ−⟩", "|Φ-⟩"):
        qc.x(0)
        qc.h(0)
        qc.cx(0, 1)
    elif bell_type == "|Ψ+⟩":
        qc.x(1)
        qc.h(0)
        qc.cx(0, 1)
    elif bell_type in ("|Ψ−⟩", "|Ψ-⟩"):
        qc.x(1)
        qc.z(0)
        qc.h(0)
        qc.cx(0, 1)
    else:
        # Default to |Φ+⟩
        qc.h(0)
        qc.cx(0, 1)

    return qc


def get_bell_statevector(bell_type="|Φ+⟩"):
    """Compute the statevector for a given Bell state."""
    qc = create_bell_circuit(bell_type)
    sv = Statevector.from_instruction(qc)
    return [round(complex(c).real, 4) + round(complex(c).imag, 4) * 1j for c in sv.data]


def get_bell_circuit_ascii(bell_type="|Φ+⟩") -> str:
    """Return text-based circuit diagram of the Bell state generator."""
    qc = create_bell_circuit(bell_type)
    return str(qc.draw(output="text"))
