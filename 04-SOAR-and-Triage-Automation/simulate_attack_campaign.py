"""
=========================================================================================
FINSECOPS-EC | SIMULADOR DE CAMPAÑA DE CIBERATAQUE FINANCIERO MULTI-ETAPA
Objetivo: Generar telemetría realista para validar defensas Blue Team & Microsoft Sentinel
Escenario: Amenaza Persistente Avanzada (APT) Financiera contra Cooperativa / Banco
Estándar 2026-2027: Simulación de Ataques Adversarios Basada en MITRE ATT&CK
=========================================================================================
"""

import sys
import json
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

LOG_FILE = Path(__file__).resolve().parent / "mock_financial_logs.json"


def simulate_full_campaign():
    print("=" * 80)
    print(" 🔴 INICIANDO SIMULACIÓN DE CAMPAÑA OFENSIVA FINANCIERA (RED TEAM REPLAY)")
    print("=" * 80)

    base_time = datetime.now(timezone.utc)
    events = []

    # ETAPA 1: Reconocimiento y Sondeo de Endpoints de Banca Virtual
    print("[*] Etapa 1: Reconocimiento perimetral y escaneo de endpoints de API...")
    events.append({
        "timestamp": (base_time - timedelta(minutes=15)).isoformat(),
        "event_id": "RECON-001",
        "source": "BancaWeb_WAF",
        "user": "anonymous_scanner",
        "ip": "185.220.101.45",
        "country": "RU",
        "action": "PROBE_API_METHODS",
        "endpoint": "/api/v1/auth/login",
        "user_agent": "python-requests/2.31.0",
        "status": "429_TOO_MANY_REQUESTS",
        "mitre": "T1595.002"
    })
    time.sleep(0.3)

    # ETAPA 2: Credential Stuffing y Robo de Sesión (AiTM Token Capture)
    print("[*] Etapa 2: Credential Stuffing y captura de sesión sin binding DPoP...")
    events.append({
        "timestamp": (base_time - timedelta(minutes=8)).isoformat(),
        "event_id": "AUTH-002",
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
    })
    time.sleep(0.3)

    # ETAPA 3: Exfiltración Masiva de Datos del Core Bancario (Insider Threat)
    print("[*] Etapa 3: Exfiltración masiva de base de socios en SQL Core...")
    events.append({
        "timestamp": (base_time - timedelta(minutes=3)).isoformat(),
        "event_id": "EXFIL-003",
        "source": "CoreBanking_DAM",
        "user": "dba_temp_support",
        "ip": "192.168.50.88",
        "action": "SELECT_BULK",
        "table": "Socios_Clientes",
        "rows_returned": 4850,
        "status": "ANOMALY_MASS_EXFILTRATION",
        "mitre": "T1530"
    })
    time.sleep(0.3)

    # ETAPA 4: Persistencia mediante Creación de Cuenta Backdoor en Active Directory
    print("[*] Etapa 4: Intento de persistencia y elevación de privilegios en Core...")
    events.append({
        "timestamp": (base_time - timedelta(minutes=1)).isoformat(),
        "event_id": "PERSIST-004",
        "source": "ActiveDirectory_Core",
        "user": "compromised_admin_svc",
        "ip": "10.100.4.12",
        "action": "ADD_MEMBER_TO_DOMAIN_ADMINS",
        "target_account": "shadow_admin_backdoor",
        "status": "PRIVILEGE_ESCALATION",
        "mitre": "T1098"
    })

    with open(LOG_FILE, "w", encoding="utf-8") as fh:
        json.dump(events, fh, indent=4)

    print("\n[+] Telemetría de ataque inyectada exitosamente en:", LOG_FILE.name)
    print("[+] Ejecutando contención automática SOAR...\n")

    # Ejecutar el motor SOAR sobre la telemetría generada
    from soc_auto_triage import FinancialSOAREngine
    engine = FinancialSOAREngine(log_path=LOG_FILE)
    engine.execute_triage()


if __name__ == "__main__":
    simulate_full_campaign()
