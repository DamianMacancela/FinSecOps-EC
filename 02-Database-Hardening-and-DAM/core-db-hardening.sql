-- =================================================================================
-- HARDENING DE MOTOR SQL Y AUDITORÍA DE ACCESO (CIS BENCHMARKS / SEPS / LOPDP)
-- =================================================================================
USE master;
GO

-- 1. Deshabilitar ejecución de comandos de SO (xp_cmdshell)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
GO

-- 2. Deshabilitar CLR Integration y OLE Automation si no se utilizan
EXEC sp_configure 'clr enabled', 0;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 0;
RECONFIGURE;
GO

-- 3. Crear Auditoría de Servidor para Eventos del Core Financiero (SEPS / LOPDP)
CREATE SERVER AUDIT Audit_CoreFinanciero_SEPS
TO FILE (FILEPATH = 'C:\SQLAudit_Logs\', MAXSIZE = 512 MB, RESERVE_DISK_SPACE = OFF)
WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);
GO

-- 4. Especificación de Auditoría de Base de Datos para accesos a tablas de PII
CREATE SERVER AUDIT SPECIFICATION Audit_CoreFinanciero_Spec
FOR SERVER AUDIT Audit_CoreFinanciero_SEPS
ADD (FAILED_LOGIN_GROUP),
ADD (SUCCESSFUL_LOGIN_GROUP),
ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
ADD (SCHEMA_OBJECT_CHANGE_GROUP);
GO

ALTER SERVER AUDIT Audit_CoreFinanciero_SEPS WITH (STATE = ON);
GO
