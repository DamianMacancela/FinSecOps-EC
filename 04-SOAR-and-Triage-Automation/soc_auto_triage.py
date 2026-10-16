import json
import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Configurar salida UTF-8 para consolas de Windows si es posible
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "mock_financial_logs.json"
REPORT_FILE = BASE_DIR / "INCIDENT_REPORT_AUTO.md"

def generate_mock_logs():
    """Genera telemetria bancaria sintetica para pruebas del SOC."""
    now = datetime.now(timezone.utc)
    logs = [
        {
            "timestamp": (now - timedelta(minutes=12)).isoformat(),
            "event_id": "EVT-9001",
            "source": "CoreBanking_DB",
            "user": "svc_corebanking_prod",
            "ip": "10.20.1.15",
            "action": "SELECT",
            "table": "Cuentas_Ahorro",
            "rows_returned": 1,
            "status": "SUCCESS"
        },
        {
            "timestamp": (now - timedelta(minutes=5)).isoformat(),
            "event_id": "EVT-9002",
            "source": "BancaWeb_WAF",
            "user": "socio_azuay_8841",
            "ip": "185.220.101.45",  # IP Tor / Maliciosa simulada
            "country": "RU",
            "action": "API_TRANSFER_REQUEST",
            "amount_usd": 9500.00,
            "mfa_Validation": "BYPASSED_TOKEN_REPLAY",
            "status": "FLAGGED"
        },
        {
            "timestamp": (now - timedelta(minutes=2)).isoformat(),
            "event_id": "EVT-9003",
            "source": "CoreBanking_DB",
            "user": "dba_temp_support",
            "ip": "192.168.50.88",
            "action": "SELECT_BULK",
            "table": "Socios_Clientes",
            "rows_returned": 4850,  # Exfiltracion masiva (> 500 registros)
            "status": "SUCCESS"
        }
    ]
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4)
    print(f"[+] Telemetria sintetica generada en: {LOG_FILE.name}")

def calculate_sha256(filepath):
    """Calcula el hash SHA-256 para preservar la Cadena de Custodia Digital."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def safe_print(text):
    """Imprime de forma segura en Windows manejando codificacion cp1252/utf-8."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))

def run_soar_triage():
    if not LOG_FILE.exists():
        generate_mock_logs()

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        events = json.load(f)

    file_hash = calculate_sha256(LOG_FILE)
    alerts = []

    safe_print("\n" + "=" * 70)
    safe_print(" [FINSECOPS-EC] MOTOR DE TRIAGE AUTOMATIZADO & SOAR (BLUE TEAM)")
    safe_print("=" * 70)
    safe_print(f"[*] Evidencia Forense (Log File): {LOG_FILE.name}")
    safe_print(f"[*] Hash SHA-256 (Cadena de Custodia): {file_hash}\n")

    for ev in events:
        # Regla 1: Exfiltracion Masiva de Datos Personales (LOPDP / SEPS)
        if ev.get("rows_returned", 0) >= 500:
            alert = {
                "severity": "CRITICAL",
                "rule": "KQL-02: Posible Exfiltracion Masiva de Datos en Core DB",
                "user": ev["user"],
                "ip": ev["ip"],
                "detail": f"Consulta masiva de {ev['rows_returned']} registros en tabla {ev['table']}.",
                "action_taken": "Cuenta suspendida en Active Directory + Sesion DB terminada (KILL SPID).",
                "compliance": "Alerta Art. 40 y 43 LOPDP (Ecuador) / ISO 27001 A.8.12"
            }
            alerts.append(alert)

        # Regla 2: Fraude Transaccional y Bypass de MFA
        if ev.get("mfa_Validation") == "BYPASSED_TOKEN_REPLAY" or ev.get("amount_usd", 0) >= 3000:
            alert = {
                "severity": "HIGH",
                "rule": "KQL-01: Anomalia Transaccional + Replay de Token de Sesion",
                "user": ev["user"],
                "ip": f"{ev['ip']} ({ev.get('country', 'N/A')})",
                "detail": f"Intento de transferencia de ${ev.get('amount_usd')} USD con token sospechoso.",
                "action_taken": "IP bloqueada en WAF + Transaccion retenida en camara de compensacion.",
                "compliance": "Norma SEPS/SB de Gestion de Riesgo Operativo y Fraude Digital"
            }
            alerts.append(alert)

    for idx, a in enumerate(alerts, 1):
        safe_print(f"[!] ALERTA #{idx} [{a['severity']}] -> {a['rule']}")
        safe_print(f"    ├── Usuario / Origen : {a['user']} @ {a['ip']}")
        safe_print(f"    ├── Hallazgo Tecnico : {a['detail']}")
        safe_print(f"    ├── Respuesta SOAR   : {a['action_taken']}")
        safe_print(f"    └── Marco Legal/GRC  : {a['compliance']}\n")

    # Generar reporte ejecutivo en Markdown automaticamente
    with open(REPORT_FILE, "w", encoding="utf-8") as rep:
        rep.write("# 🚨 Reporte Automatizado de Incidente y Cadena de Custodia\n\n")
        rep.write(f"- **Fecha UTC:** `{datetime.now(timezone.utc).isoformat()}`\n")
        rep.write(f"- **Archivo de Evidencia:** `{LOG_FILE.name}`\n")
        rep.write(f"- **Hash SHA-256 (Integridad Forense):** `{file_hash}`\n\n")
        rep.write("## Incidentes Contenidos por el Motor SOAR\n\n")
        for a in alerts:
            rep.write(f"### [{a['severity']}] {a['rule']}\n")
            rep.write(f"- **Entidad Comprometida:** `{a['user']}` (`{a['ip']}`)\n")
            rep.write(f"- **Detalle:** {a['detail']}\n")
            rep.write(f"- **Acción de Contención:** {a['action_taken']}\n")
            rep.write(f"- **Impacto Normativo:** {a['compliance']}\n\n")

    safe_print(f"[+] Reporte tecnico-legal exportado en: {REPORT_FILE.name}")
    safe_print("=" * 70 + "\n")

if __name__ == "__main__":
    run_soar_triage()
