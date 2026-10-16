-- =================================================================================
-- HARDENING Y ENMASCARAMIENTO DINÁMICO DE DATOS (CUMPLIMIENTO LOPDP ECUADOR & SEPS)
-- Objetivo: Impedir que analistas de soporte o atacantes vean datos sensibles en claro
-- =================================================================================

CREATE SCHEMA CoreFinanciero;
GO

CREATE TABLE CoreFinanciero.Socios_Clientes (
    SocioID INT IDENTITY(1,1) PRIMARY KEY,
    Cedula_Identidad VARCHAR(10) MASKED WITH (FUNCTION = 'partial(2,"XXXXXX",2)') NOT NULL,
    Nombre_Completo NVARCHAR(120) NOT NULL,
    Numero_Cuenta VARCHAR(12) MASKED WITH (FUNCTION = 'partial(0,"XXXXXXXX",4)') NOT NULL,
    Correo_Electronico VARCHAR(100) MASKED WITH (FUNCTION = 'email()') NULL,
    Saldo_Disponible DECIMAL(12,2) MASKED WITH (FUNCTION = 'default()') NOT NULL
);
GO

-- Crear rol de soporte técnico / desarrollo con privilegios mínimos (Zero Trust)
CREATE ROLE Rol_Soporte_N1;
GRANT SELECT ON SCHEMA::CoreFinanciero TO Rol_Soporte_N1;
-- Nota: Rol_Soporte_N1 NO recibe permiso UNMASK, por lo que verá "01XXXXXX89" en Cédula.
