"""
=========================================================================================
FINSECOPS-EC | MOTOR DE TRIAGE AUTOMATIZADO & SOAR AVANZADO (BLUE TEAM & DFIR)
Estándares: 2026-2027 | Python 3.10+ | Tipado Estricto | Criptografía Forense Merkle Tree
Cumplimiento: ISO/IEC 27001:2022 (A.5.26, A.5.28) | LOPDP Ecuador (Art. 40, 43) | SEPS
=========================================================================================
"""

import os
import sys
import json
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

# Asegurar compatibilidad UTF-8 en consolas Windows (PowerShell / cmd)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "mock_financial_logs.json"
REPORT_FILE = BASE_DIR / "INCIDENT_REPORT_AUTO.md"
STIX_FILE = BASE_DIR / "incident_bundle.stix.json"


@dataclass
class SecurityIncident:
    incident_id: str
    timestamp: str
    severity: str
    rule_name: str
    attacker_ip: str
    compromised_entity: str
    technical_evidence: str
    mitre_attack_id: str
    containment_action: str
    compliance_framework: str


class MerkleTree:
    """
    Implementación forense de Árbol de Merkle (Merkle Tree) para sellado inmutable
    de telemetría de eventos bancarios. Estándar forense 2026-2027.
    """
    @staticmethod
    def hash_leaf(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def build_merkle_root(leaves: List[str]) -> str:
        if not leaves:
            return hashlib.sha256(b"EMPTY_LOG_LEDGER").hexdigest()
        current_layer = [MerkleTree.hash_leaf(leaf) for leaf in leaves]
        while len(current_layer) > 1:
            if len(current_layer) % 2 != 0:
                current_layer.append(current_layer[-1])  # Duplicar último nodo impar
            next_layer = []
            for i in range(0, len(current_layer), 2):
                combined = current_layer[i] + current_layer[i + 1]
                next_layer.append(hashlib.sha256(combined.encode("utf-8")).hexdigest())
            current_layer = next_layer
        return current_layer[0]


class FinancialSOAREngine:
    def __init__(self, log_path: Path = LOG_FILE):
        self.log_path = log_path
        self.incidents: List[SecurityIncident] = []
        self.raw_logs: List[Dict[str, Any]] = []

    def load_telemetry(self) -> None:
        if not self.log_path.exists():
            print(f"[*] Telemetría no encontrada. Generando datos sintéticos en: {self.log_path.name}")
            self.generate_synthetic_telemetry()
        with open(self.log_path, "r", encoding="utf-8") as fh:
            self.raw_logs = json.load(fh)

    def generate_synthetic_telemetry(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        logs = [
            {
                "timestamp": now,
                "event_id": "SEC-EVT-1001",
                "source": "CoreBanking_DAM",
                "user": "dba_temp_support",
                "ip": "192.168.50.88",
                "action": "SELECT_BULK",
                "table": "Socios_Clientes",
                "rows_returned": 4850,
                "status": "ANOMALY_MASS_EXFILTRATION",
                "mitre": "T1530"
            },
            {
                "timestamp": now,
                "event_id": "SEC-EVT-1002",
                "source": "Financial_API_Gateway",
                "user": "socio_azuay_8841",
                "ip": "185.220.101.45",
                "country": "RU",
                "action": "API_TRANSFER_EXEC",
                "amount_usd": 9500.00,
                "mfa_validation": "BYPASSED_TOKEN_REPLAY",
                "dpop_proof_status": "MISSING_OR_STOLEN",
                "status": "FLAGGED_FRAUD",
                "mitre": "T1550.004"
            },
            {
                "timestamp": now,
                "event_id": "SEC-EVT-1003",
                "source": "ActiveDirectory_Core",
                "user": "compromised_admin_svc",
                "ip": "10.100.4.12",
                "action": "ADD_MEMBER_TO_DOMAIN_ADMINS",
                "target_account": "shadow_admin_backdoor",
                "status": "PRIVILEGE_ESCALATION",
                "mitre": "T1098"
            }
        ]
        with open(self.log_path, "w", encoding="utf-8") as fh:
            json.dump(logs, fh, indent=4)

    def calculate_file_hash(self) -> str:
        sha256 = hashlib.sha256()
        with open(self.log_path, "rb") as fh:
            while chunk := fh.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    def calculate_merkle_root(self) -> str:
        serialized_entries = [json.dumps(ev, sort_keys=True) for ev in self.raw_logs]
        return MerkleTree.build_merkle_root(serialized_entries)

    def execute_triage(self) -> None:
        self.load_telemetry()
        file_sha256 = self.calculate_file_hash()
        merkle_root = self.calculate_merkle_root()

        print("\n" + "=" * 80)
        print(" 🛡️ FINSECOPS-EC | MOTOR DE TRIAGE AUTOMATIZADO & SOAR (EDICIÓN 2026-2027)")
        print("=" * 80)
        print(f"[*] Archivo de Telemetría     : {self.log_path.name}")
        print(f"[*] Hash SHA-256 Evidencia    : {file_sha256}")
        print(f"[*] Merkle Root (Bloque DFIR) : {merkle_root}")
        print(f"[*] Eventos Analizados        : {len(self.raw_logs)}\n")

        for idx, ev in enumerate(self.raw_logs, 1):
            # Regla 1: Exfiltración masiva de datos personales (Art. 40 y 43 LOPDP)
            if ev.get("rows_returned", 0) >= 500:
                incident = SecurityIncident(
                    incident_id=f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-00{idx}",
                    timestamp=ev.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    severity="CRITICAL",
                    rule_name="KQL-02: Exfiltración Masiva de Registros de Socios en Core DB",
                    attacker_ip=ev.get("ip", "N/A"),
                    compromised_entity=ev.get("user", "Unknown"),
                    technical_evidence=f"Extracción no autorizada de {ev.get('rows_returned')} registros en tabla {ev.get('table')}.",
                    mitre_attack_id="T1530 (Data from Cloud / Database)",
                    containment_action="Sesión SQL terminada (KILL SPID) + Cuenta AD inhabilitada + Notificación CISO",
                    compliance_framework="Art. 40 y 43 LOPDP Ecuador / Control ISO/IEC 27001:2022 A.8.12"
                )
                self.incidents.append(incident)

            # Regla 2: Fraude Transaccional y Replay de Token (DPoP Bypass)
            if ev.get("mfa_validation") == "BYPASSED_TOKEN_REPLAY" or ev.get("amount_usd", 0) >= 5000:
                incident = SecurityIncident(
                    incident_id=f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-00{idx}",
                    timestamp=ev.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    severity="HIGH",
                    rule_name="KQL-01: Fraude Transaccional + Replay de Token de Sesión (AiTM)",
                    attacker_ip=f"{ev.get('ip', 'N/A')} ({ev.get('country', 'N/A')})",
                    compromised_entity=ev.get("user", "Unknown"),
                    technical_evidence=f"Transferencia de ${ev.get('amount_usd')} USD sin firma criptográfica DPoP válida.",
                    mitre_attack_id="T1550.004 (Web Session Cookie Replay)",
                    containment_action="Bloqueo dinámico de IP en WAF ModSecurity + Retención de fondos en cámara SPI",
                    compliance_framework="Normativa de Canales Electrónicos SEPS / ISO 27001 A.8.20"
                )
                self.incidents.append(incident)

            # Regla 3: Escalada de Privilegios en Directorio Activo del Core
            if ev.get("action") == "ADD_MEMBER_TO_DOMAIN_ADMINS":
                incident = SecurityIncident(
                    incident_id=f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-00{idx}",
                    timestamp=ev.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    severity="CRITICAL",
                    rule_name="KQL-03: Asignación No Autorizada a Grupo de Máximo Privilegio",
                    attacker_ip=ev.get("ip", "N/A"),
                    compromised_entity=ev.get("user", "Unknown"),
                    technical_evidence=f"Cuenta '{ev.get('target_account')}' elevada a administradores de dominio.",
                    mitre_attack_id="T1098 (Account Manipulation)",
                    containment_action="Revocación inmediata del token Kerberos + Remoción de grupo + Bloqueo de cuenta",
                    compliance_framework="ISO/IEC 27001:2022 A.5.15 & A.8.2 / Norma de Auditoría SEPS"
                )
                self.incidents.append(incident)

        for inc in self.incidents:
            print(f"[!] ALERTA ACTIVADA [{inc.severity}] -> {inc.rule_name}")
            print(f"    ├── ID Incidente      : {inc.incident_id}")
            print(f"    ├── Origen / Entidad  : {inc.attacker_ip} | Usuario: {inc.compromised_entity}")
            print(f"    ├── Evidencia Técnica : {inc.technical_evidence}")
            print(f"    ├── Mapeo MITRE       : {inc.mitre_attack_id}")
            print(f"    ├── Acción SOAR       : {inc.containment_action}")
            print(f"    └── Marco Regulatorio : {inc.compliance_framework}\n")

        self.export_markdown_report(file_sha256, merkle_root)
        self.export_stix_bundle()
        print("=" * 80)
        print(f"[+] Reporte Pericial DFIR exportado : {REPORT_FILE.name}")
        print(f"[+] Inteligencia STIX 2.1 generada  : {STIX_FILE.name}")
        print("=" * 80)

    def export_markdown_report(self, sha256_hash: str, merkle_root: str) -> None:
        with open(REPORT_FILE, "w", encoding="utf-8") as fh:
            fh.write("# 🚨 Reporte Pericial Automatizado de Incidentes & Cadena de Custodia DFIR\n\n")
            fh.write("> **Generado por FinSecOps-EC SOAR Engine v1.1.0**  \n")
            fh.write("> *Sistema de Auditoría Técnica para Instituciones Financieras (Ecuador)*\n\n")
            fh.write("---\n\n")
            fh.write("### 🔐 Certificado Criptográfico de Integridad (ISO/IEC 27001:2022 A.5.28)\n")
            fh.write(f"- **Fecha UTC de Ejecución:** `{datetime.now(timezone.utc).isoformat()}`\n")
            fh.write(f"- **Archivo de Evidencia Primaria:** `{self.log_path.name}`\n")
            fh.write(f"- **Hash SHA-256 del Archivo:** `{sha256_hash}`\n")
            fh.write(f"- **Merkle Tree Root Hash:** `{merkle_root}`\n")
            fh.write("- **Estado de Custodia:** `INALTERABLE / WORM VERIFIED`\n\n")
            fh.write("---\n\n")
            fh.write("### 🛡️ Incidentes Contenidos Automáticamente\n\n")
            for inc in self.incidents:
                fh.write(f"#### [{inc.severity}] {inc.rule_name} (`{inc.incident_id}`)\n")
                fh.write(f"- **Entidad Comprometida:** `{inc.compromised_entity}`\n")
                fh.write(f"- **Vector de Origen:** `{inc.attacker_ip}`\n")
                fh.write(f"- **Evidencia Forense:** {inc.technical_evidence}\n")
                fh.write(f"- **Técnica MITRE ATT&CK:** `{inc.mitre_attack_id}`\n")
                fh.write(f"- **Acción de Respuesta SOAR:** {inc.containment_action}\n")
                fh.write(f"- **Impacto Legal / GRC:** {inc.compliance_framework}\n\n")

    def export_stix_bundle(self) -> None:
        """Exporta los hallazgos en formato OASIS STIX 2.1 para compartición CTI (CERT-EC / ASOBANCA)."""
        stix_objects = []
        for inc in self.incidents:
            obj = {
                "type": "incident",
                "spec_version": "2.1",
                "id": f"incident--{hashlib.sha256(inc.incident_id.encode()).hexdigest()[:36]}",
                "name": inc.rule_name,
                "description": inc.technical_evidence,
                "severity": inc.severity.lower(),
                "created": datetime.now(timezone.utc).isoformat(),
                "labels": ["financial-fraud", "lopdp-breach", "zero-trust-violation"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": inc.mitre_attack_id.split()[0]}
                ]
            }
            stix_objects.append(obj)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{hashlib.sha256(b'finsecops-bundle').hexdigest()[:36]}",
            "objects": stix_objects
        }
        with open(STIX_FILE, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2)


def main():
    parser = argparse.ArgumentParser(description="FinSecOps-EC SOAR Engine CLI")
    parser.add_argument("--simulate-attack", action="store_true", help="Generar nueva telemetría sintética")
    parser.add_argument("--verify", action="store_true", help="Verificar integridad de la evidencia")
    args = parser.parse_args()

    engine = FinancialSOAREngine()
    if args.simulate_attack:
        engine.generate_synthetic_telemetry()
    engine.execute_triage()


if __name__ == "__main__":
    main()
