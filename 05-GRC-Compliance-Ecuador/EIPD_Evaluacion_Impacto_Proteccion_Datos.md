# ⚖️ Evaluación de Impacto en la Protección de Datos Personales (EIPD / DPIA)
## Sistema de Monitoreo Transaccional & Core Financiero (FinSecOps-EC)

> **Marco Jurídico Aplicable:** Ley Orgánica de Protección de Datos Personales (LOPDP Ecuador, Registro Oficial Suplemento 459)  
> **Directrices:** Guía Oficial de Evaluación de Impacto emitida por la Superintendencia de Protección de Datos Personales (SPDP)  
> **Estándar Técnico:** ISO/IEC 27701:2019 (PIMS) & ISO/IEC 27001:2022 (A.5.34 Privacidad y Protección de PII)

---

### 1. Descripción del Tratamiento de Datos Personales
* **Responsable del Tratamiento:** Institución Financiera (Banco / Cooperativa de Ahorro y Crédito Segmento 1).
* **Finalidad:** Detección de fraude transaccional en tiempo real, mitigación de robo de cuentas bancarias (Account Takeover) y cumplimiento de requerimientos de trazabilidad de la SEPS y Superintendencia de Bancos.
* **Categorías de Datos Tratados:**
  1. *Datos de Identificación:* Cédula de Identidad / RUC, Nombres Completos, Correo Electrónico.
  2. *Datos Financieros:* Número de cuenta, Saldo disponible, Historial de montos transferidos.
  3. *Datos de Telemetría Técnica:* Direcciones IP, País de origen (GeoIP), Hashes de tokens de sesión (DPoP), Identificadores de dispositivo y huellas TLS (JA4).

---

### 2. Análisis de Necesidad y Proporcionalidad (Art. 10 y 11 LOPDP)
| Criterio Legal | Justificación Técnica Implementada en FinSecOps-EC |
|:---|:---|
| **Principio de Minimización** | La base de datos aplica **Dynamic Data Masking (DDM)** en `data-masking-lopdp.sql`. Los analistas de soporte N1 solo visualizan `01XXXXXX89` y no la cédula en claro. |
| **Seguridad desde el Diseño (Art. 37)** | Implementación de **Zero Trust Network Policies** (`zero-trust-network-policy.yaml`) que aíslan las bases de datos impidiendo accesos laterales directos. |
| **Conservación Limitada** | Los logs de telemetría son retenidos conforme al plazo pericial exigido por la SEPS, sellados con Árbol de Merkle para evitar su alteración. |

---

### 3. Matriz de Evaluación de Riesgos para los Derechos de los Titulares
| Riesgo Identificado | Probabilidad | Impacto | Nivel Inherente | Medida Mitigante en FinSecOps-EC | Nivel Residual |
|:---|:---:|:---:|:---:|:---|:---:|
| **R1: Exfiltración masiva de base de socios por un Administrador de BD (Insider)** | Media | Crítico | **ALTO** | Regla KQL-02 (alerta $\ge 500$ filas) + Deshabilitación de `xp_cmdshell` + Row-Level Security (RLS). | **BAJO** |
| **R2: Secuestro de sesión y suplantación de identidad mediante phishing AiTM** | Alta | Alto | **ALTO** | Reglas WAF DPoP RFC 9449 (`dpop-oauth2-hardening.conf`) + Correlación KQL de discrepancia de ASN. | **BAJO** |
| **R3: Manipulación no autorizada de saldos o registros contables** | Baja | Crítico | **ALTO** | Tablas criptográficas SQL Ledger (`ledger-tamperproof-audit.sql`) con verificación `sp_verify_database_ledger`. | **MUY BAJO** |

---

### 4. Protocolo Obligatorio ante Vulneraciones de Seguridad (Art. 43 LOPDP)
En caso de que el motor SOAR (`soc_auto_triage.py`) active una alerta `CRITICAL` confirmada:
1. **Triage y Contención Inmediata ($t_0$ a $t_2$ horas):** Desconexión de sesiones activas, aislamiento de cuentas y preservación del Hash SHA-256 / Merkle Root del log.
2. **Determinación del Alcance ($t_2$ a $t_24$ horas):** Cuantificación de titulares afectados y categorías de datos expuestos.
3. **Notificación Formal a la SPDP y SEPS ($t \le 72$ horas hábiles):** Envío del expediente pericial `INCIDENT_REPORT_AUTO.md` firmado digitalmente, detallando medidas correctivas y plan de remediación.
