-- =========================================================================================
-- SEGURIDAD A NIVEL DE FILAS (ROW-LEVEL SECURITY - RLS) EN CORE BANCARIO
-- Principio: Privilegio Mínimo (Zero Trust Data Access) & Need-to-Know
-- Cumplimiento: LOPDP Art. 40 (Segregación Jurisdiccional) / ISO 27001 A.5.15
-- =========================================================================================

USE CoreFinanciero_SecureDB;
GO

-- 1. Tabla de Usuarios y Socios con Atributo de Sucursal / Jurisdicción
CREATE SCHEMA BancaSegmento;
GO

CREATE TABLE BancaSegmento.SociosRegional
(
    SocioID INT IDENTITY(1,1) PRIMARY KEY,
    Cedula VARCHAR(10) NOT NULL,
    Nombre NVARCHAR(100) NOT NULL,
    ProvinciaOperativa VARCHAR(30) NOT NULL, -- 'Azuay', 'Pichincha', 'Guayas', 'Loja'
    SaldoUSD DECIMAL(15,2) NOT NULL
);
GO

-- 2. Función Predicado de Seguridad (Inline Table-Valued Function)
-- Determina en tiempo de ejecución si el usuario de base de datos puede ver la fila
CREATE SCHEMA SecPolicy;
GO

CREATE FUNCTION SecPolicy.fn_FiltroSucursalSocio(@ProvinciaOperativa AS VARCHAR(30))
    RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS fn_access_result
WHERE 
    -- 1. Administrador Central de Cumplimiento / Auditoría Externa SEPS
    IS_MEMBER('Rol_Oficial_Cumplimiento_Nacional') = 1
    -- 2. O la sucursal del socio coincide con la sesión autenticada del empleado
    OR @ProvinciaOperativa = CAST(SESSION_CONTEXT(N'ProvinciaOperativa') AS VARCHAR(30));
GO

-- 3. Crear y Activar la Política de Seguridad (Security Policy)
-- Impide de raíz ataques de exfiltración masiva por operadores de agencias locales
CREATE SECURITY POLICY SecPolicy.PoliticaAccesoPorSucursal
ADD FILTER PREDICATE SecPolicy.fn_FiltroSucursalSocio(ProvinciaOperativa)
ON BancaSegmento.SociosRegional
WITH (STATE = ON, SCHEMABINDING = ON);
GO

-- 4. Ejemplo de Validación Práctica:
-- EXEC sp_set_session_context 'ProvinciaOperativa', 'Azuay';
-- SELECT * FROM BancaSegmento.SociosRegional; 
-- (El resultado mostrará ÚNICAMENTE los registros de Azuay, bloqueando el resto automáticamente)
