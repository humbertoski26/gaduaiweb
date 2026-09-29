import os
import psycopg2
import psycopg2.extras


def get_conn():
    url = os.environ["DATABASE_URL"]
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    conn = psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)
    conn.autocommit = True
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS colegios (
  id SERIAL PRIMARY KEY,
  nombre TEXT NOT NULL,
  comuna TEXT,
  creado_en TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS usuarios_colegio (
  id SERIAL PRIMARY KEY,
  colegio_id INTEGER NOT NULL REFERENCES colegios(id) ON DELETE CASCADE,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  creado_en TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS accesos (
  id SERIAL PRIMARY KEY,
  colegio_id INTEGER NOT NULL REFERENCES colegios(id) ON DELETE CASCADE,
  producto TEXT NOT NULL CHECK (producto IN ('relacionai','triage','gaduai')),
  habilitado BOOLEAN NOT NULL DEFAULT false,
  url TEXT,
  UNIQUE(colegio_id, producto)
);

-- Código de acceso que el personal escribe en gaduai.cl/entrar.html para llegar al GADUAI
-- de su colegio. Lo define Humberto en el panel; único sin importar mayúsculas.
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS codigo_acceso TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS colegios_codigo_acceso_unico
  ON colegios (upper(codigo_acceso)) WHERE codigo_acceso IS NOT NULL;

-- Ficha del colegio: vigencia del contrato con GADUAI.
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS fecha_inicio DATE;
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS fecha_termino DATE;

CREATE TABLE IF NOT EXISTS mensajes_contacto (
  id SERIAL PRIMARY KEY,
  nombre TEXT NOT NULL,
  correo TEXT NOT NULL,
  mensaje TEXT NOT NULL,
  leido BOOLEAN NOT NULL DEFAULT false,
  creado_en TIMESTAMP DEFAULT now()
);

-- CRM comercial: cada organización (colegio, sostenedor, municipio) es un solo registro que
-- avanza por el embudo hasta ser cliente; así nada se escribe dos veces. Los colegios que ya
-- existían quedan como clientes.
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS tipo TEXT NOT NULL DEFAULT 'colegio';
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS etapa TEXT NOT NULL DEFAULT 'cliente';
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS es_demo BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS contacto_nombre TEXT;
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS contacto_cargo TEXT;
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS contacto_correo TEXT;
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS contacto_telefono TEXT;
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS valor_mensual INTEGER;
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS proximo_paso TEXT;
ALTER TABLE colegios ADD COLUMN IF NOT EXISTS proximo_paso_fecha DATE;

-- Historial de la relación: reuniones, llamadas, correos, demostraciones y notas.
CREATE TABLE IF NOT EXISTS interacciones (
  id SERIAL PRIMARY KEY,
  colegio_id INTEGER NOT NULL REFERENCES colegios(id) ON DELETE CASCADE,
  fecha DATE NOT NULL DEFAULT CURRENT_DATE,
  tipo TEXT NOT NULL,
  nota TEXT NOT NULL,
  creado_en TIMESTAMP DEFAULT now()
);
CREATE INDEX IF NOT EXISTS interacciones_colegio_idx ON interacciones (colegio_id, fecha DESC);

-- Mensaje de gaduai.cl convertido en prospecto: queda enlazado a su organización.
ALTER TABLE mensajes_contacto ADD COLUMN IF NOT EXISTS colegio_id INTEGER REFERENCES colegios(id) ON DELETE SET NULL;
"""


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(SCHEMA)
    cur.close()
    conn.close()
