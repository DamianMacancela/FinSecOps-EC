# 🚨 Reporte Pericial Automatizado de Incidentes & Cadena de Custodia DFIR

> **Generado por FinSecOps-EC SOAR Engine v1.1.0**  
> *Sistema de Auditoría Técnica para Instituciones Financieras (Ecuador)*

---

### 🔐 Certificado Criptográfico de Integridad (ISO/IEC 27001:2022 A.5.28)
- **Fecha UTC de Ejecución:** `2026-10-16T23:02:17.095287+00:00`
- **Archivo de Evidencia Primaria:** `mock_financial_logs.json`
- **Hash SHA-256 del Archivo:** `7aef3f62ae84570476a4efd5bb18f1c19cdd24a3641318df929dd4487bcd6e52`
- **Merkle Tree Root Hash:** `5d117f7e0c12f2e0ea105f9ceb54c0eee9f86b7301c034867b6d75624861425d`
- **Estado de Custodia:** `INALTERABLE / WORM VERIFIED`

---

### 🛡️ Incidentes Contenidos Automáticamente

#### [HIGH] KQL-01: Fraude Transaccional + Replay de Token de Sesión (AiTM) (`INC-20261016-002`)
- **Entidad Comprometida:** `socio_azuay_8841`
- **Vector de Origen:** `185.220.101.45 (RU)`
- **Evidencia Forense:** Transferencia de $9500.0 USD sin firma criptográfica DPoP válida.
- **Técnica MITRE ATT&CK:** `T1550.004 (Web Session Cookie Replay)`
- **Acción de Respuesta SOAR:** Bloqueo dinámico de IP en WAF ModSecurity + Retención de fondos en cámara SPI
- **Impacto Legal / GRC:** Normativa de Canales Electrónicos SEPS / ISO 27001 A.8.20

#### [CRITICAL] KQL-02: Exfiltración Masiva de Registros de Socios en Core DB (`INC-20261016-003`)
- **Entidad Comprometida:** `dba_temp_support`
- **Vector de Origen:** `192.168.50.88`
- **Evidencia Forense:** Extracción no autorizada de 4850 registros en tabla Socios_Clientes.
- **Técnica MITRE ATT&CK:** `T1530 (Data from Cloud / Database)`
- **Acción de Respuesta SOAR:** Sesión SQL terminada (KILL SPID) + Cuenta AD inhabilitada + Notificación CISO
- **Impacto Legal / GRC:** Art. 40 y 43 LOPDP Ecuador / Control ISO/IEC 27001:2022 A.8.12

#### [CRITICAL] KQL-03: Asignación No Autorizada a Grupo de Máximo Privilegio (`INC-20261016-004`)
- **Entidad Comprometida:** `compromised_admin_svc`
- **Vector de Origen:** `10.100.4.12`
- **Evidencia Forense:** Cuenta 'shadow_admin_backdoor' elevada a administradores de dominio.
- **Técnica MITRE ATT&CK:** `T1098 (Account Manipulation)`
- **Acción de Respuesta SOAR:** Revocación inmediata del token Kerberos + Remoción de grupo + Bloqueo de cuenta
- **Impacto Legal / GRC:** ISO/IEC 27001:2022 A.5.15 & A.8.2 / Norma de Auditoría SEPS

