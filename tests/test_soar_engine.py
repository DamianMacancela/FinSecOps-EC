"""
=========================================================================================
UNIT TESTS & VERIFICACIÓN DE INTEGRIDAD FORENSE | FINSECOPS-EC SOAR
Ejecución: python -m unittest tests/test_soar_engine.py
Compatibilidad: Python unittest (StdLib) & pytest | Cero dependencias externas
=========================================================================================
"""

import sys
import os
import json
import unittest
import tempfile
from pathlib import Path

# Incluir ruta del motor SOAR en sys.path
SOAR_DIR = Path(__file__).resolve().parent.parent / "04-SOAR-and-Triage-Automation"
sys.path.insert(0, str(SOAR_DIR))

from soc_auto_triage import MerkleTree, FinancialSOAREngine, SecurityIncident


class TestSOAREngineAndForensics(unittest.TestCase):

    def test_merkle_tree_deterministic_root(self):
        """Verifica que el cálculo de la raíz de Merkle sea determinista e inmutable."""
        leaves = [
            "EVENT_001_LOGIN_SUCCESS_192.168.1.1",
            "EVENT_002_TRANSFER_ATTEMPT_USD_9500",
            "EVENT_003_SQL_BULK_EXFILTRATION_4850"
        ]
        root1 = MerkleTree.build_merkle_root(leaves)
        root2 = MerkleTree.build_merkle_root(leaves)
        self.assertEqual(root1, root2)
        self.assertEqual(len(root1), 64)  # Formato SHA-256 en hexadecimal

    def test_merkle_tree_detects_tampering(self):
        """Verifica que cualquier alteración en un evento altere la raíz del árbol Merkle."""
        leaves_orig = ["EVENT_001_VALID", "EVENT_002_VALID"]
        leaves_tampered = ["EVENT_001_VALID", "EVENT_002_TAMPERED"]
        self.assertNotEqual(
            MerkleTree.build_merkle_root(leaves_orig),
            MerkleTree.build_merkle_root(leaves_tampered)
        )

    def test_soar_triage_exfiltration_detection(self):
        """Verifica que el motor SOAR active la alerta CRITICAL ante exfiltración masiva."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as tf:
            sample_data = [
                {
                    "timestamp": "2026-10-16T18:00:00Z",
                    "event_id": "TEST-01",
                    "source": "CoreBanking_DAM",
                    "user": "malicious_insider",
                    "ip": "10.0.0.99",
                    "rows_returned": 1200,
                    "table": "Socios_Clientes"
                }
            ]
            json.dump(sample_data, tf)
            temp_path = Path(tf.name)

        try:
            engine = FinancialSOAREngine(log_path=temp_path)
            engine.execute_triage()
            crit_alert = next((inc for inc in engine.incidents if inc.severity == "CRITICAL"), None)
            self.assertIsNotNone(crit_alert)
            self.assertIn("Exfiltración Masiva", crit_alert.rule_name)
            self.assertTrue(crit_alert.mitre_attack_id.startswith("T1530"))
        finally:
            if temp_path.exists():
                os.remove(temp_path)

    def test_soar_triage_fraud_detection(self):
        """Verifica que el motor SOAR active la alerta HIGH ante intento de fraude transaccional."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as tf:
            sample_data = [
                {
                    "timestamp": "2026-10-16T18:00:00Z",
                    "event_id": "TEST-02",
                    "source": "Financial_API_Gateway",
                    "user": "victim_user",
                    "ip": "185.220.101.45",
                    "country": "RU",
                    "amount_usd": 7500.00,
                    "mfa_validation": "BYPASSED_TOKEN_REPLAY"
                }
            ]
            json.dump(sample_data, tf)
            temp_path = Path(tf.name)

        try:
            engine = FinancialSOAREngine(log_path=temp_path)
            engine.execute_triage()
            fraud_alert = next((inc for inc in engine.incidents if inc.severity == "HIGH"), None)
            self.assertIsNotNone(fraud_alert)
            self.assertIn("Fraude Transaccional", fraud_alert.rule_name)
            self.assertIn("WAF ModSecurity", fraud_alert.containment_action)
        finally:
            if temp_path.exists():
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
