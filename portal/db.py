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
"""


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(SCHEMA)
    cur.close()
    conn.close()
