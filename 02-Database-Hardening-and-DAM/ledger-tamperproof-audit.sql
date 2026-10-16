-- =========================================================================================
-- TABLAS LEDGER CRIPTOGRÁFICAS E INMUTABILIDAD DE TRANSACCIONES (ESTÁNDAR 2026-2027)
-- Base de Datos: CoreFinanciero_DB | Cumplimiento: LOPDP Art. 40 / SEPS Riesgo Operativo
-- Tecnología: SQL Server Ledger / Criptografía de Bloques SHA-256 Inalterable
-- =========================================================================================

USE master;
GO

-- 1. Crear Base de Datos con Ledger habilitado por defecto (Toda tabla hereda inmutabilidad)
-- Evita que incluso usuarios con rol sysadmin o 'sa' alteren balances contables sin dejar huella criptográfica.
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'CoreFinanciero_SecureDB')
BEGIN
    CREATE DATABASE CoreFinanciero_SecureDB
    WITH LEDGER = ON;
END
GO

USE CoreFinanciero_SecureDB;
GO

-- 2. Esquema Financiero de Alta Seguridad
CREATE SCHEMA AuditoriaForense;
GO

-- 3. Tabla de Transacciones Financieras con Libro Mayor Actualizable (Updatable Ledger Table)
-- Genera automáticamente una tabla histórica (_LedgerHistoryTable) sellada con Merkle Tree
CREATE TABLE AuditoriaForense.TransaccionesBancarias_Ledger
(
    TransaccionID BIGINT IDENTITY(1,1) PRIMARY KEY CLUSTERED,
    CuentaOrigen VARCHAR(12) NOT NULL,
    CuentaDestino VARCHAR(12) NOT NULL,
    MontoTransferido DECIMAL(18,2) NOT NULL,
    CanalTransaccional VARCHAR(30) NOT NULL, -- 'BancaWeb_API', 'ATM', 'Ventanilla'
    DireccionIP_Origen VARCHAR(45) NOT NULL,
    HashDPoP_Token VARCHAR(64) NOT NULL,     -- Hash SHA-256 del token DPoP utilizado
    FechaTransaccion DATETIME2(7) NOT NULL DEFAULT (SYSUTCDATETIME())
)
WITH 
(
    SYSTEM_VERSIONING = ON (HISTORY_TABLE = AuditoriaForense.TransaccionesBancarias_Historial),
    LEDGER = ON (LEDGER_VIEW = AuditoriaForense.TransaccionesBancarias_LedgerView)
);
GO

-- 4. Verificación Criptográfica Forense (Para Auditorías de la SEPS y Fiscalía General)
-- Este procedimiento verifica si los bloques de la base de datos coinciden con los digests inmutables.
CREATE PROCEDURE AuditoriaForense.sp_VerificarIntegridadCriptografica
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Procedimiento del sistema que valida los hashes SHA-256 de cada transacción
    -- Genera error pericial si un atacante modificó datos mediante inyección binaria directa
    EXEC sp_verify_database_ledger;
    
    SELECT 
        ledger_view.TransaccionID,
        ledger_view.CuentaOrigen,
        ledger_view.MontoTransferido,
        ledger_view.ledger_start_transaction_id,
        ledger_view.ledger_start_sequence_number,
        ledger_view.ledger_operation_type_desc
    FROM AuditoriaForense.TransaccionesBancarias_LedgerView ledger_view
    ORDER BY ledger_view.TransaccionID DESC;
END;
GO
