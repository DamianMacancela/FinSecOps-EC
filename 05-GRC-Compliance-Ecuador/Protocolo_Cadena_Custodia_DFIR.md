# 🛡️ Protocolo Forense DFIR y Preservación de Cadena de Custodia Digital

## 1. Adquisición Inmutable (WORM)
Ante una alerta de severidad `CRITICAL` o `HIGH` en Microsoft Sentinel o en el motor SOAR, se congela de inmediato el archivo de auditoría (`.json` / `.sqlaudit` / `.evtx`) en almacenamiento de solo lectura (WORM - Write Once, Read Many).

## 2. Sellado Criptográfico (Control ISO/IEC 27001:2022 A.5.28)
Se genera el hash **SHA-256** de forma inmediata previo a cualquier interacción o análisis sobre la evidencia. Este hash se registra en el acta formal de transferencia de custodia digital junto con:
- Marca de tiempo UTC (`ISO 8601`).
- Identificador único de caso o incidente.
- Analista de guardia del SOC y responsable de custodia.

## 3. Ventana Legal de Notificación de Brechas (Art. 43 LOPDP Ecuador)
Conforme al **Artículo 43 de la Ley Orgánica de Protección de Datos Personales (LOPDP)**:
- Toda vulneración de seguridad que comprometa datos personales de socios o clientes y pueda entrañar un riesgo para sus derechos debe notificarse a la **Autoridad de Protección de Datos Personales** en el término máximo legal.
- Paralelamente, se notifica al organismo de control financiero (**SEPS** o **Superintendencia de Bancos**) conforme a las resoluciones de riesgo operativo vigentes.
- Se adjunta como evidencia inmutable el informe pericial técnico `INCIDENT_REPORT_AUTO.md` firmado con el hash SHA-256 correspondiente.
