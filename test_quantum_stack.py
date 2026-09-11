import unittest
import numpy as np
from app import app
from database.db import init_db
from quantum.bell_state import create_bell_circuit, get_bell_statevector, BELL_STATES
from quantum.pauli_operations import correction_for_bits, get_qiskit_pauli
from quantum.teleportation import simulate_teleportation
from quantum.pennylane_engine import evaluate_quantum_threat


class QuantumStackTests(unittest.TestCase):
    def setUp(self):
        init_db()
        self.client = app.test_client()

    def test_bell_states(self):
        for bs in BELL_STATES:
            qc = create_bell_circuit(bs)
            self.assertEqual(qc.num_qubits, 2)
            sv = get_bell_statevector(bs)
            self.assertEqual(len(sv), 4)
            # Verify normalized statevector
            norm = sum(abs(c) ** 2 for c in sv)
            self.assertAlmostEqual(norm, 1.0, places=3)

    def test_pauli_corrections(self):
        self.assertEqual(correction_for_bits("00"), "I")
        self.assertEqual(correction_for_bits("01"), "X")
        self.assertEqual(correction_for_bits("10"), "Z")
        self.assertEqual(correction_for_bits("11"), "XZ")
        op = get_qiskit_pauli("X")
        self.assertEqual(op.dim, (2, 2))

    def test_teleportation_ideal_and_noisy(self):
        ideal = simulate_teleportation("Confidential Payload", "Alice", eavesdrop=False)
        self.assertEqual(ideal["backend"], "qiskit-aer (AerSimulator)")
        self.assertGreater(ideal["measurement_match"], 80.0)
        self.assertIn("q_0:", ideal["circuit_diagram"])

        noisy = simulate_teleportation("Confidential Payload", "Alice", eavesdrop=True)
        self.assertLess(noisy["measurement_match"], 80.0)
        self.assertTrue(noisy["eavesdropped"])

    def test_pennylane_threat_classifier(self):
        # Benign test
        benign = evaluate_quantum_threat(
            message="Valid message", signer="Alice", fidelity=0.98, is_consumed=False, is_authorized=True
        )
        self.assertLess(benign["threat_score"], 20.0)
        self.assertFalse(benign["is_anomalous"])

        # Attack test (unauthorized impersonator Mallory)
        attack = evaluate_quantum_threat(
            message="Forged message", signer="Mallory", fidelity=0.98, is_consumed=False, is_authorized=False
        )
        self.assertGreater(attack["threat_score"], 80.0)
        self.assertTrue(attack["is_anomalous"])

    def test_api_endpoints(self):
        # 1. Quantum Status
        res = self.client.get("/api/quantum-status")
        self.assertEqual(res.status_code, 200)
        q_data = res.get_json()
        self.assertTrue(q_data["ok"])
        self.assertIn("qiskit_version", q_data)
        self.assertIn("pennylane_version", q_data)
        self.assertIn("aer_version", q_data)

        # 2. Generate
        gen = self.client.post("/api/generate", json={"message": "System Auth Token", "signer": "Alice"})
        self.assertEqual(gen.status_code, 200)
        sig = gen.get_json()["signature"]
        session_id = sig["session_id"]
        self.assertIn("circuit_diagram", sig)
        self.assertIn("qnn_threat_score", sig)

        # 3. Signature Details
        details = self.client.get(f"/api/signature/{session_id}")
        self.assertEqual(details.status_code, 200)
        self.assertEqual(details.get_json()["signature"]["signer"], "Alice")

        # 4. Verify
        ver = self.client.post("/api/verify", json={"session_id": session_id, "verifier": "Bob"})
        self.assertEqual(ver.status_code, 200)
        self.assertEqual(ver.get_json()["decision"], "ACCEPT")

        # 5. Replay Attack Detection
        replay = self.client.post("/api/verify", json={"session_id": session_id, "verifier": "Bob"})
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.get_json()["decision"], "REJECT")
        self.assertEqual(replay.get_json()["category"], "REPLAY")

        # 6. Attack Simulation
        att = self.client.post("/api/attack", json={"session_id": session_id, "attack_type": "channel", "attacker": "Eve"})
        self.assertEqual(att.status_code, 200)
        self.assertEqual(att.get_json()["decision"], "REJECT")
        self.assertEqual(att.get_json()["category"], "CHANNEL_MANIPULATION")


if __name__ == "__main__":
    unittest.main()
