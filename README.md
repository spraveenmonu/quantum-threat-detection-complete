# Quantum-Secured Cyber Threat Detection Platform

A hybrid quantum computing cybersecurity platform demonstrating quantum digital signatures (QDS), Bennett teleportation protocols, and variational quantum anomaly detection.

## Quantum Computing Stack
- **Qiskit 2.x**: Quantum circuit design, Bell-state preparation ($|\Phi^+\rangle, |\Phi^-\rangle, |\Psi^+\rangle, |\Psi^-\rangle$), and Pauli correction operators.
- **Qiskit Aer (AerSimulator)**: Statevector quantum simulation of 3-qubit teleportation protocols, fidelity calculations, and quantum channel eavesdropping noise models.
- **PennyLane 0.45**: Variational Quantum Classifier (VQC) using parameterized quantum circuits (`AngleEmbedding` + `StronglyEntanglingLayers`) to classify threat anomalies in quantum Hilbert space.
- **Flask 3.1 & SQLite**: Lightweight REST API, parameterized database, and interactive cybersecurity dashboard.

---

## Architecture & Features

1. **🔐 3-Qubit Quantum Teleportation Signing (`/api/generate`)**
   - Derives Bloch sphere angles $(\theta, \phi)$ from the message's SHA-256 hash and signer identity.
   - Entangles a shared Bell pair ($q_1, q_2$) and executes Bell basis measurement on $(q_0, q_1)$.
   - Evaluates Pauli correction ($I, X, Z, XZ$) on $q_2$ and computes real state fidelity on `AerSimulator`.
   - Computes baseline PennyLane QNN anomaly score.

2. **✅ 6-Stage Quantum Verification Protocol (`/api/verify`)**
   - Stage 1: Session existence & anti-forgery
   - Stage 2: Role-based verifier authorization (Bob, Charlie)
   - Stage 3: Anti-replay enforcement (one-time quantum token consumption)
   - Stage 4: Channel integrity check (Qiskit Aer statevector fidelity $> 80\%$)
   - Stage 5: Cryptographic SHA-256 hash binding integrity
   - Stage 6: PennyLane VQC quantum anomaly classification

3. **⚔️ Attack Simulation & Eavesdropping Interception (`/api/attack`)**
   - **Channel Manipulation**: Simulates Eve measuring the transit qubit, collapsing entanglement and degrading fidelity below 80%.
   - **Signature Forgery**: Alters message payload; detected by hash binding & PennyLane entropy checks.
   - **Identity Impersonation**: Attacker (Mallory) blocked by quantum identity subspace mapping.
   - **Replay Attack**: Blocked by quantum single-use token consumption.
   - **Unauthorized Access**: Blocked by role-based authorization verification.

4. **⚛️ Quantum Engine Status (`/api/quantum-status`)**
   - Live telemetry of active Qiskit, Aer, and PennyLane devices and circuit architectures.

---

## Setup & Run

1. Activate your environment or create a virtual environment:
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Launch application:
   ```bash
   python app.py
   ```
   Or use the provided PowerShell helper:
   ```powershell
   .\run.ps1
   ```

4. Open `http://127.0.0.1:5000` in your web browser.
