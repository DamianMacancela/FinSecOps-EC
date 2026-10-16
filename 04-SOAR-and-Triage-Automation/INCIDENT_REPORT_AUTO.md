# 🚨 Reporte Automatizado de Incidente y Cadena de Custodia

- **Fecha UTC:** `2026-10-16T21:56:56.995440+00:00`
- **Archivo de Evidencia:** `mock_financial_logs.json`
- **Hash SHA-256 (Integridad Forense):** `dc4f9ab94afb70499a318f6c236be5dd9f423e0b91d44b2b4b121ae5b9254b71`

## Incidentes Contenidos por el Motor SOAR

### [HIGH] KQL-01: Anomalia Transaccional + Replay de Token de Sesion
- **Entidad Comprometida:** `socio_azuay_8841` (`185.220.101.45 (RU)`)
- **Detalle:** Intento de transferencia de $9500.0 USD con token sospechoso.
- **Acción de Contención:** IP bloqueada en WAF + Transaccion retenida en camara de compensacion.
- **Impacto Normativo:** Norma SEPS/SB de Gestion de Riesgo Operativo y Fraude Digital

### [CRITICAL] KQL-02: Posible Exfiltracion Masiva de Datos en Core DB
- **Entidad Comprometida:** `dba_temp_support` (`192.168.50.88`)
- **Detalle:** Consulta masiva de 4850 registros en tabla Socios_Clientes.
- **Acción de Contención:** Cuenta suspendida en Active Directory + Sesion DB terminada (KILL SPID).
- **Impacto Normativo:** Alerta Art. 40 y 43 LOPDP (Ecuador) / ISO 27001 A.8.12

