# ⚖️ Matriz de Trazabilidad Técnica y Cumplimiento Normativo (Ecuador)

Esta matriz vincula cada control técnico implementado en **FinSecOps-EC** con las exigencias regulatorias vigentes para el sector financiero (Bancos y Cooperativas Segmento 1) en el Ecuador:

| Artefacto Técnico en Repo | Técnica MITRE ATT&CK | Control ISO/IEC 27001:2022 | Normativa SEPS / Sup. de Bancos | Ley Orgánica de Protección de Datos (LOPDP) |
| :--- | :--- | :--- | :--- | :--- |
| **`waf-custom-rules.conf`** | `T1110` Credential Stuffing / `T1190` API Exploit | **A.8.20** Seguridad de redes y **A.8.26** Requerimientos en aplicaciones | Seguridad en canales electrónicos y validación transaccional | **Art. 37** Seguridad de datos personales desde el diseño y por defecto |
| **`core-db-hardening.sql`** | `T1059` Command Execution / `T1562` Disable Logs | **A.8.9** Gestión de configuración y **A.8.15** Generación de registros (Logs) | Pistas de auditoría inalterables en servidores del Core Financiero | **Art. 39** Evaluación de impacto y control de infraestructura crítica |
| **`data-masking-lopdp.sql`** | `T1005` Data from Local System (Insider Threat) | **A.8.11** Enmascaramiento de datos y **A.5.15** Control de acceso | Segregación de funciones entre Desarrollo, Soporte N1 y Producción | **Art. 40** Obligación de seudonimización y cifrado de datos sensibles |
| **`01_ImpossibleTravel_Fraud.kql`** | `T1078` Valid Accounts / `T1550.004` Session Cookie | **A.8.16** Actividades de monitoreo y **A.5.17** Información de autenticación | Monitoreo continuo de patrones de fraude en banca virtual y móvil | Protección patrimonial y confidencialidad del titular financiero |
| **`02_MassDataExfiltration_DB.kql`** | `T1530` Data from Cloud / Core Repository | **A.8.12** Prevención de fuga de datos (DLP en Base de Datos) | Detección temprana de extracción no autorizada de base de socios | **Art. 43** Detección para notificación de vulneraciones de seguridad |
| **`soc_auto_triage.py`** | Mitigación post-compromiso y preservación DFIR | **A.5.26** Respuesta a incidentes y **A.5.28** Recolección de evidencia | Plan de contingencia y gestión de incidentes de riesgo operativo | Integridad probatoria (Hash SHA-256) ante auditoría regulatoria |
