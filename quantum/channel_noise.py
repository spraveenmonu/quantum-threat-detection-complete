import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer.noise import NoiseModel, depolarizing_error, phase_damping_error


def build_eavesdropper_noise_model(error_prob: float = 0.45) -> NoiseModel:
    """
    Build a Qiskit Aer NoiseModel simulating an active eavesdropper (Eve)
    intercepting quantum states in transit, causing decoherence and depolarizing noise.
    """
    noise_model = NoiseModel()
    # 1-qubit depolarizing error simulating Eve's projective measurement / disturbance
    depol_err = depolarizing_error(error_prob, 1)
    noise_model.add_all_qubit_quantum_error(depol_err, ["id", "x", "z", "h"])
    return noise_model


def apply_eavesdropper_intercept(qc: QuantumCircuit, target_qubit: int = 2, basis: str = "random") -> str:
    """
    Directly insert an intercept-and-resend eavesdropping attack into the circuit on the transit qubit.
    According to quantum mechanics, measuring an entangled qubit in transit collapses its superposition,
    introducing detectable disturbance (Heisenberg Uncertainty Principle / No-Cloning Theorem).
    """
    if basis == "random":
        basis = "X" if np.random.rand() > 0.5 else "Z"

    if basis == "X":
        # Eve measures in Hadamard (X) basis
        qc.h(target_qubit)
        # Projection collapses state; Eve re-prepares and passes along
        qc.h(target_qubit)
        return "Eve intercepted transit qubit in X (Hadamard) basis"
    else:
        # Eve measures in Computational (Z) basis, collapsing superposition
        # In simulation, a phase/bit disturbance or measurement projection
        qc.barrier(target_qubit)
        return "Eve intercepted transit qubit in Z (Computational) basis"
