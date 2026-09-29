import hmac
import json
import os
import re
import time
import unicodedata
from datetime import date, datetime, timedelta
from functools import wraps
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Flask, render_template, request, redirect, url_for, session, jsonify

from db import get_conn, init_db

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Auditoría de seguridad: límite simple de intentos por IP en los dos logins de este panel
# (colegio y super-admin) — mismo patrón que en Relacionai y en GADUAI.
_intentos = {}


def limite_intentos(clave_ruta, tope=20, ventana_seg=900):
    def decorador(vista):
        @wraps(vista)
        def envoltura(*args, **kwargs):
            ip = request.headers.get("X-Forwarded-For", request.remote_addr or "desconocida").split(",")[0].strip()
            k = (clave_ruta, ip)
            ahora = time.time()
            n, desde = _intentos.get(k, (0, ahora))
            if ahora - desde > ventana_seg:
                n, desde = 0, ahora
            n += 1
            _intentos[k] = (n, desde)
            if n > tope:
                from flask import abort
                abort(429)
            return vista(*args, **kwargs)
        return envoltura
    return decorador

PRODUCTOS = {
    "relacionai": {"nombre": "Relacionai", "descripcion": "Gestión de convivencia escolar y casos."},
    "triage": {"nombre": "TRIAGE GADUAI", "descripcion": "Timeline y triage de la gestión del colegio."},
    "gaduai": {"nombre": "GADUAI", "descripcion": "Plataforma multi-perfil del colegio: timeline, entrevista formal y más — un despliegue propio por colegio, como Relacionai."},
}

TRIAGE_BASE_URL = (os.environ.get("TRIAGE_BASE_URL") or "https://triage-gaduai.onrender.com").rstrip("/")
TRIAGE_ADMIN_KEY = os.environ.get("TRIAGE_ADMIN_KEY")


def slug_colegio(nombre):
    """Debe producir el mismo id que la función slug() de TRIAGE (server.js) para el mismo
    nombre, porque ahí es donde vive de verdad el colegio: TRIAGE deriva su id a partir del
    nombre, nosotros solo lo recalculamos para saber qué link armar."""
    s = unicodedata.normalize("NFD", nombre or "").encode("ascii", "ignore").decode("ascii").lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s


class TriageError(Exception):
    pass


def activar_colegio_en_triage(nombre, comuna):
    """Crea (o reconoce, si ya existe) el colegio en TRIAGE GADUAI y devuelve el link directo
    a su login (?colegio=<id>) más las credenciales del usuario máster, si se acaban de crear.
    Lanza TriageError si TRIAGE no está configurado o no responde."""
    if not TRIAGE_ADMIN_KEY:
        raise TriageError("Falta configurar TRIAGE_ADMIN_KEY en este servicio.")
    body = json.dumps({"nombre": nombre, "comuna": comuna}).encode("utf-8")
    req = Request(
        f"{TRIAGE_BASE_URL}/api/colegios",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "X-Admin-Key": TRIAGE_ADMIN_KEY},
    )
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return {
            "id": data["id"],
            "url": f"{TRIAGE_BASE_URL}/?colegio={data['id']}",
            "master": data.get("master"),
        }
    except HTTPError as exc:
        if exc.code == 409:
            colegio_id = slug_colegio(nombre)
            return {"id": colegio_id, "url": f"{TRIAGE_BASE_URL}/?colegio={colegio_id}", "master": None}
        raise TriageError(f"TRIAGE respondió con error ({exc.code}).") from exc
    except URLError as exc:
        raise TriageError("No se pudo conectar con TRIAGE.") from exc


def resetear_master_en_triage(colegio_id_triage, correo_nuevo=None):
    """Genera una clave nueva para el usuario máster de un colegio que ya existe en TRIAGE —
    para cuando la clave mostrada al habilitar TRIAGE la primera vez ("se muestra una sola
    vez") se perdió antes de guardarla. Devuelve las credenciales nuevas o lanza TriageError."""
    if not TRIAGE_ADMIN_KEY:
        raise TriageError("Falta configurar TRIAGE_ADMIN_KEY en este servicio.")
    body = json.dumps({"correoNuevo": correo_nuevo} if correo_nuevo else {}).encode("utf-8")
    req = Request(
        f"{TRIAGE_BASE_URL}/api/colegios/{colegio_id_triage}/reset-master",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "X-Admin-Key": TRIAGE_ADMIN_KEY},
    )
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["master"]
    except HTTPError as exc:
        if exc.code == 404:
            raise TriageError("Ese colegio todavía no está activado en TRIAGE.") from exc
        raise TriageError(f"TRIAGE respondió con error ({exc.code}).") from exc
    except URLError as exc:
        raise TriageError("No se pudo conectar con TRIAGE.") from exc

# El formulario de contacto y la caja de código de entrada viven en el sitio público (otro
# origen), así que esos endpoints necesitan CORS para recibir el POST desde gaduai.cl.
ALLOWED_ORIGINS = {"https://gaduai.cl", "https://www.gaduai.cl", "https://gaduai-web.onrender.com"}


@app.after_request
def add_cors_headers(resp):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Max-Age"] = "600"
    return resp

with app.app_context():
    init_db()


def admin_login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*a, **kw)
    return wrapper


# ---------- entrada del personal: código de colegio ----------
# El personal ya no entra aquí con una clave compartida por colegio: en gaduai.cl/entrar.html
# escribe el código de su colegio, este endpoint lo valida y devuelve el link al GADUAI de ese
# colegio, donde cada persona inicia sesión con su propia cuenta. Desde fuera no se puede ver
# ni listar ningún colegio: un código equivocado solo responde "no válido".
ENTRAR_URL = "https://www.gaduai.cl/entrar.html"
CODIGO_RE = re.compile(r"^[A-Z0-9-]{4,24}$")
_fallos_codigo = {}          # ip -> (fallos, desde)
_fallos_codigo_global = [0, time.time()]
FALLOS_CODIGO_IP = 10        # por IP cada 15 minutos
FALLOS_CODIGO_GLOBAL = 300   # entre todas las IP cada 15 minutos (frena adivinar desde muchas IP)


def normalizar_codigo(codigo):
    return re.sub(r"\s+", "", codigo or "").upper()


def destino_colegio(cur, colegio_id):
    """Link de entrada del colegio: su GADUAI (propio o compartido) si está habilitado; si
    solo tiene el TRIAGE compartido habilitado, ese link. None si no tiene ninguno."""
    cur.execute(
        "SELECT producto, url FROM accesos WHERE colegio_id = %s AND habilitado AND url IS NOT NULL",
        (colegio_id,),
    )
    urls = {r["producto"]: r["url"] for r in cur.fetchall()}
    return urls.get("gaduai") or urls.get("triage")


@app.route("/api/entrar", methods=["POST", "OPTIONS"])
def api_entrar():
    if request.method == "OPTIONS":
        return ("", 204)
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "desconocida").split(",")[0].strip()
    ahora = time.time()
    n, desde = _fallos_codigo.get(ip, (0, ahora))
    if ahora - desde > 900:
        n, desde = 0, ahora
    if ahora - _fallos_codigo_global[1] > 900:
        _fallos_codigo_global[:] = [0, ahora]
    if n >= FALLOS_CODIGO_IP or _fallos_codigo_global[0] >= FALLOS_CODIGO_GLOBAL:
        return jsonify({"error": "demasiados_intentos"}), 429

    data = request.get_json(silent=True) or {}
    codigo = normalizar_codigo(data.get("codigo"))
    destino = None
    if CODIGO_RE.match(codigo):
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, nombre FROM colegios WHERE upper(codigo_acceso) = %s", (codigo,))
        colegio = cur.fetchone()
        if colegio:
            url = destino_colegio(cur, colegio["id"])
            if url:
                destino = {"url": url, "nombre": colegio["nombre"]}
        cur.close()
        conn.close()
    if not destino:
        _fallos_codigo[ip] = (n + 1, desde)
        _fallos_codigo_global[0] += 1
        return jsonify({"error": "codigo_invalido"}), 404
    return jsonify(destino)


# La antigua entrada con correo y clave compartida por colegio se retiró: cualquier link
# viejo a esta pantalla lleva a la caja de código de gaduai.cl.
@app.route("/")
@app.route("/login", methods=["GET", "POST"])
@app.route("/portal")
@app.route("/logout")
def login():
    session.pop("colegio_id", None)
    return redirect(ENTRAR_URL)


# ---------- admin ----------

AVISO_VENCIMIENTO_DIAS = 60  # desde cuándo el panel avisa que un contrato está por vencer


def estado_contrato(fecha_termino):
    """Estado del contrato según su fecha de término, para mostrarlo en el panel:
    (texto, clase de color). Solo informa; no bloquea el acceso del colegio."""
    if not fecha_termino:
        return ("Sin fecha de término", "chip-off")
    if isinstance(fecha_termino, str):
        fecha_termino = date.fromisoformat(fecha_termino[:10])
    dias = (fecha_termino - date.today()).days
    if dias < 0:
        return (f"Vencido hace {-dias} día{'s' if dias != -1 else ''}", "chip-peligro")
    if dias == 0:
        return ("Vence hoy", "chip-warn")
    if dias <= AVISO_VENCIMIENTO_DIAS:
        return (f"Vence en {dias} día{'s' if dias != 1 else ''}", "chip-warn")
    return ("Vigente", "chip-ok")


def fecha_o_none(texto):
    try:
        return date.fromisoformat((texto or "").strip()) if (texto or "").strip() else None
    except ValueError:
        return False

@app.route("/admin/login", methods=["GET", "POST"])
@limite_intentos("admin_login")
def admin_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        email_ok = hmac.compare_digest(email.encode(), os.environ["ADMIN_EMAIL"].strip().lower().encode())
        password_ok = hmac.compare_digest(password.encode(), os.environ["ADMIN_PASSWORD"].encode())
        if email_ok and password_ok:
            session["is_admin"] = True
            return redirect(url_for("admin_hoy"))
        return render_template("admin_login.html", error="Correo o clave incorrectos.")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


# ---------- formulario de contacto público (llamado desde gaduai.cl) ----------

# Aviso por correo de cada solicitud del formulario público — antes solo quedaba
# guardada en mensajes_contacto y nadie se enteraba sin entrar a /admin/mensajes.
# Va por la API HTTP de Resend (no SMTP): Render bloquea las conexiones SMTP
# salientes de sus servicios web, así que un smtplib.SMTP normal nunca conecta.
# Si RESEND_API_KEY no está configurada, no se envía nada (no rompe el
# formulario): el mensaje igual queda guardado en la base de datos.
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
CONTACTO_EMAIL_TO = os.environ.get("CONTACTO_EMAIL_TO", "gaduaichile@gmail.com")


def enviar_correo_admin(asunto, texto, reply_to=None):
    """Correo a la casilla de GADUAI (CONTACTO_EMAIL_TO) vía Resend. Sin RESEND_API_KEY no hace nada."""
    if not RESEND_API_KEY or not CONTACTO_EMAIL_TO:
        return
    datos = {"from": "GADUAI <onboarding@resend.dev>", "to": [CONTACTO_EMAIL_TO], "subject": asunto, "text": texto}
    if reply_to:
        datos["reply_to"] = reply_to
    payload = json.dumps(datos).encode("utf-8")
    req = Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
            # Sin esto, Cloudflare bloquea la petición (error 1010) porque el
            # User-Agent por defecto de urllib se detecta como firma de bot.
            "User-Agent": "gaduai-portal/1.0",
        },
        method="POST",
    )
    with urlopen(req, timeout=10) as resp:
        resp.read()


def enviar_aviso_contacto(nombre, correo, mensaje):
    enviar_correo_admin(
        f"Nueva solicitud desde gaduai.cl — {nombre}",
        f"Nombre: {nombre}\nCorreo: {correo}\n\nMensaje:\n{mensaje}\n\n— Enviado desde el formulario de gaduai.cl",
        reply_to=correo,
    )


@app.route("/api/contacto", methods=["POST", "OPTIONS"])
def api_contacto():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(silent=True) or request.form
    nombre = (data.get("nombre") or "").strip()
    correo = (data.get("correo") or "").strip()
    mensaje = (data.get("mensaje") or "").strip()
    if not nombre or not correo or not mensaje:
        return jsonify({"error": "Complete todos los campos."}), 400
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO mensajes_contacto (nombre, correo, mensaje) VALUES (%s, %s, %s)",
        (nombre, correo, mensaje),
    )
    cur.close()
    conn.close()
    try:
        enviar_aviso_contacto(nombre, correo, mensaje)
    except HTTPError as e:
        app.logger.error(f"No se pudo enviar el aviso de contacto: {e} — {e.read().decode('utf-8', 'replace')}")
    except Exception as e:
        app.logger.error(f"No se pudo enviar el aviso de contacto: {e}")
    return jsonify({"ok": True})


@app.route("/admin/mensajes")
@admin_login_required
def admin_mensajes():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM mensajes_contacto ORDER BY creado_en DESC")
    mensajes = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("admin_mensajes.html", mensajes=mensajes)


@app.route("/admin/mensajes/<int:mensaje_id>/leido", methods=["POST"])
@admin_login_required
def admin_marcar_leido(mensaje_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE mensajes_contacto SET leido = true WHERE id = %s", (mensaje_id,))
    cur.close()
    conn.close()
    return redirect(url_for("admin_mensajes"))


# ---------- CRM comercial ----------
# Cada organización (colegio, sostenedor, municipio) es un solo registro que avanza por el
# embudo hasta ser cliente: la ficha comercial y la de accesos son la misma, así nada se
# escribe dos veces. Vive solo en este panel: los colegios nunca ven estos datos.
ETAPAS = [("contacto", "Contacto"), ("reunion", "Reunión"), ("demo", "Demostración"),
          ("propuesta", "Propuesta"), ("cliente", "Cliente"), ("perdido", "Perdido")]
ETAPA_NOMBRE = dict(ETAPAS)
ETAPAS_EMBUDO = ["contacto", "reunion", "demo", "propuesta"]
TIPOS = [("colegio", "Colegio"), ("sostenedor", "Sostenedor / red"), ("municipio", "Municipio / SLEP"), ("otro", "Otro")]
TIPO_NOMBRE = dict(TIPOS)
TIPOS_INTERACCION = [("reunion", "Reunión"), ("llamada", "Llamada"), ("correo", "Correo"),
                     ("demo", "Demostración"), ("nota", "Nota")]
TIPO_INTERACCION_NOMBRE = dict(TIPOS_INTERACCION)
PANEL_URL = "https://gaduai-portal.onrender.com/admin"


def a_fecha(valor):
    """Fecha de la base (date, datetime o texto ISO) como date; None si no hay."""
    if not valor:
        return None
    if isinstance(valor, datetime):
        return valor.date()
    if isinstance(valor, date):
        return valor
    return date.fromisoformat(str(valor)[:10])


def estado_paso(fecha):
    """Urgencia del próximo paso: (texto, clase de color) o None si no tiene fecha."""
    f = a_fecha(fecha)
    if not f:
        return None
    dias = (f - date.today()).days
    if dias < 0:
        return (f"Atrasado {-dias} día{'s' if dias != -1 else ''}", "chip-peligro")
    if dias == 0:
        return ("Hoy", "chip-warn")
    if dias == 1:
        return ("Mañana", "chip-info")
    return (f"En {dias} días", "chip-info")


@app.template_filter("clp")
def formato_clp(n):
    return "$" + f"{int(n or 0):,}".replace(",", ".")


@app.template_filter("fecha")
def formato_fecha(valor):
    f = a_fecha(valor)
    return f.strftime("%d-%m-%Y") if f else ""


@app.context_processor
def contexto_crm():
    return {"ETAPAS": ETAPAS, "ETAPA_NOMBRE": ETAPA_NOMBRE, "TIPOS": TIPOS, "TIPO_NOMBRE": TIPO_NOMBRE,
            "TIPOS_INTERACCION": TIPOS_INTERACCION, "TIPO_INTERACCION_NOMBRE": TIPO_INTERACCION_NOMBRE,
            "hoy": date.today()}


def volver_a(colegio_id):
    """Vuelve a la pantalla desde donde se hizo la acción (Hoy, Embudo) o a la ficha."""
    destino = request.form.get("volver") or ""
    if destino.startswith("/admin") and "//" not in destino:
        return destino
    return url_for("admin_colegio", colegio_id=colegio_id)


def registrar_interaccion(cur, colegio_id, tipo, nota, fecha=None):
    cur.execute(
        "INSERT INTO interacciones (colegio_id, fecha, tipo, nota) VALUES (%s, %s, %s, %s)",
        (colegio_id, fecha or date.today(), tipo, nota),
    )


def resumen_crm(cur):
    """Todo lo que alimenta la pantalla Hoy y el correo diario."""
    hoy = date.today()
    cur.execute("SELECT * FROM colegios ORDER BY nombre")
    orgs = cur.fetchall()
    for o in orgs:
        o["paso"] = estado_paso(o.get("proximo_paso_fecha"))
    activos = [o for o in orgs if o["etapa"] == "cliente" and not o["es_demo"]]
    embudo = [o for o in orgs if o["etapa"] in ETAPAS_EMBUDO]
    pasos = sorted(
        [o for o in orgs if o.get("proximo_paso") and o.get("proximo_paso_fecha") and o["etapa"] != "perdido"
         and a_fecha(o["proximo_paso_fecha"]) <= hoy + timedelta(days=7)],
        key=lambda o: a_fecha(o["proximo_paso_fecha"]),
    )
    renovaciones = sorted(
        [o for o in activos if o.get("fecha_termino")
         and a_fecha(o["fecha_termino"]) <= hoy + timedelta(days=AVISO_VENCIMIENTO_DIAS)],
        key=lambda o: a_fecha(o["fecha_termino"]),
    )
    for o in renovaciones:
        o["contrato"] = estado_contrato(o.get("fecha_termino"))
    cur.execute("SELECT * FROM mensajes_contacto WHERE leido = false AND colegio_id IS NULL ORDER BY creado_en DESC")
    mensajes = cur.fetchall()
    return {
        "atrasados": [o for o in pasos if a_fecha(o["proximo_paso_fecha"]) < hoy],
        "de_hoy": [o for o in pasos if a_fecha(o["proximo_paso_fecha"]) == hoy],
        "semana": [o for o in pasos if a_fecha(o["proximo_paso_fecha"]) > hoy],
        "sin_paso": [o for o in embudo if not o.get("proximo_paso")],
        "renovaciones": renovaciones,
        "mensajes": mensajes,
        "n_clientes": len(activos),
        "ingreso": sum(o.get("valor_mensual") or 0 for o in activos),
        "n_embudo": len(embudo),
        "valor_embudo": sum(o.get("valor_mensual") or 0 for o in embudo),
    }


@app.route("/admin")
@admin_login_required
def admin_hoy():
    conn = get_conn()
    cur = conn.cursor()
    r = resumen_crm(cur)
    cur.close()
    conn.close()
    return render_template("admin_hoy.html", r=r)


@app.route("/admin/embudo")
@admin_login_required
def admin_embudo():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM colegios ORDER BY proximo_paso_fecha NULLS LAST, nombre")
    orgs = cur.fetchall()
    cur.close()
    conn.close()
    columnas = {e: [] for e, _ in ETAPAS}
    for o in orgs:
        o["paso"] = estado_paso(o.get("proximo_paso_fecha"))
        columnas.setdefault(o["etapa"], []).append(o)
    totales = {e: sum(o.get("valor_mensual") or 0 for o in lista) for e, lista in columnas.items()}
    return render_template("admin_embudo.html", columnas=columnas, totales=totales)


@app.route("/admin/organizaciones")
@admin_login_required
def admin_dashboard():
    filtro = request.args.get("filtro", "todas")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM colegios ORDER BY nombre")
    colegios = cur.fetchall()
    cur.execute("SELECT COUNT(*) AS n FROM mensajes_contacto WHERE leido = false")
    mensajes_no_leidos = cur.fetchone()["n"]
    cur.execute("SELECT * FROM accesos")
    accesos_por_colegio = {}
    for row in cur.fetchall():
        accesos_por_colegio.setdefault(row["colegio_id"], {})[row["producto"]] = row["habilitado"]
    cur.close()
    conn.close()

    for c in colegios:
        c["acc"] = accesos_por_colegio.get(c["id"], {})
        # Entrada activa: tiene código y una plataforma GADUAI (propia o compartida) habilitada.
        c["listo"] = bool(c.get("codigo_acceso") and (c["acc"].get("gaduai") or c["acc"].get("triage")))
        c["contrato"] = estado_contrato(c.get("fecha_termino"))
    filtros = {
        "clientes": lambda c: c["etapa"] == "cliente",
        "embudo": lambda c: c["etapa"] in ETAPAS_EMBUDO,
        "perdidas": lambda c: c["etapa"] == "perdido",
    }
    total = len(colegios)
    if filtro in filtros:
        colegios = [c for c in colegios if filtros[filtro](c)]
    return render_template("admin_dashboard.html", colegios=colegios, total=total, filtro=filtro,
                           mensajes_no_leidos=mensajes_no_leidos)


@app.route("/admin/colegios/nuevo", methods=["GET", "POST"])
@admin_login_required
def admin_nuevo_colegio():
    if request.method == "POST":
        nombre = request.form["nombre"].strip()
        comuna = request.form.get("comuna", "").strip() or None
        tipo = request.form.get("tipo") if request.form.get("tipo") in TIPO_NOMBRE else "colegio"
        etapa = request.form.get("etapa") if request.form.get("etapa") in ETAPA_NOMBRE else "contacto"
        contacto = (request.form.get("contacto_nombre") or "").strip() or None
        correo = (request.form.get("contacto_correo") or "").strip() or None
        if not nombre:
            return render_template("admin_nuevo_colegio.html", error="Escribe el nombre de la organización.")
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                """INSERT INTO colegios (nombre, comuna, tipo, etapa, contacto_nombre, contacto_correo)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (nombre, comuna, tipo, etapa, contacto, correo),
            )
            colegio_id = cur.fetchone()["id"]
            registrar_interaccion(cur, colegio_id, "nota", f"Organización creada en etapa {ETAPA_NOMBRE[etapa]}.")
        except Exception:
            cur.close()
            conn.close()
            return render_template("admin_nuevo_colegio.html", error="No se pudo crear la organización.")
        cur.close()
        conn.close()
        return redirect(url_for("admin_colegio", colegio_id=colegio_id))
    return render_template("admin_nuevo_colegio.html")


@app.route("/admin/colegios/<int:colegio_id>")
@admin_login_required
def admin_colegio(colegio_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM colegios WHERE id = %s", (colegio_id,))
    colegio = cur.fetchone()
    if not colegio:
        cur.close()
        conn.close()
        return redirect(url_for("admin_dashboard"))
    cur.execute("SELECT * FROM accesos WHERE colegio_id = %s", (colegio_id,))
    rows = cur.fetchall()
    destino = destino_colegio(cur, colegio_id)
    cur.execute("SELECT * FROM interacciones WHERE colegio_id = %s ORDER BY fecha DESC, id DESC", (colegio_id,))
    historial = cur.fetchall()
    cur.close()
    conn.close()

    acc = {}
    for row in rows:
        acc[row["producto"]] = row["habilitado"]
        acc[f"{row['producto']}_url"] = row["url"]

    return render_template("admin_colegio.html", colegio=colegio, acc=acc, destino=destino, historial=historial,
                           paso=estado_paso(colegio.get("proximo_paso_fecha")),
                           contrato=estado_contrato(colegio.get("fecha_termino")), msg=request.args.get("msg"))


@app.route("/admin/colegios/<int:colegio_id>/ficha", methods=["POST"])
@admin_login_required
def admin_ficha_colegio(colegio_id):
    """Ficha comercial: tipo, contacto principal, valor mensual, demo, comuna y vigencia del contrato."""
    f = request.form
    comuna = (f.get("comuna") or "").strip() or None
    inicio = fecha_o_none(f.get("fecha_inicio"))
    termino = fecha_o_none(f.get("fecha_termino"))
    if inicio is False or termino is False:
        return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg="Ficha no guardada: revisa las fechas."))
    if inicio and termino and termino < inicio:
        return redirect(url_for("admin_colegio", colegio_id=colegio_id,
                                msg="Ficha no guardada: la fecha de término es anterior a la de inicio."))
    valor_txt = re.sub(r"[^0-9]", "", f.get("valor_mensual") or "")
    valor = int(valor_txt) if valor_txt else None
    tipo = f.get("tipo") if f.get("tipo") in TIPO_NOMBRE else "colegio"
    campos = [(f.get(k) or "").strip()[:200] or None
              for k in ("contacto_nombre", "contacto_cargo", "contacto_correo", "contacto_telefono")]
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """UPDATE colegios SET comuna = %s, fecha_inicio = %s, fecha_termino = %s, tipo = %s, valor_mensual = %s,
           es_demo = %s, contacto_nombre = %s, contacto_cargo = %s, contacto_correo = %s, contacto_telefono = %s
           WHERE id = %s""",
        (comuna, inicio, termino, tipo, valor, f.get("es_demo") == "1", *campos, colegio_id),
    )
    cur.close()
    conn.close()
    return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg="Ficha guardada."))


@app.route("/admin/colegios/<int:colegio_id>/etapa", methods=["POST"])
@admin_login_required
def admin_etapa(colegio_id):
    etapa = request.form.get("etapa")
    if etapa not in ETAPA_NOMBRE:
        return redirect(volver_a(colegio_id))
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT etapa FROM colegios WHERE id = %s", (colegio_id,))
    fila = cur.fetchone()
    if fila and fila["etapa"] != etapa:
        cur.execute("UPDATE colegios SET etapa = %s WHERE id = %s", (etapa, colegio_id))
        registrar_interaccion(cur, colegio_id, "nota",
                              f"Pasó de {ETAPA_NOMBRE.get(fila['etapa'], fila['etapa'])} a {ETAPA_NOMBRE[etapa]}.")
    cur.close()
    conn.close()
    return redirect(volver_a(colegio_id))


@app.route("/admin/colegios/<int:colegio_id>/proximo", methods=["POST"])
@admin_login_required
def admin_proximo_paso(colegio_id):
    """Comprometer: define el próximo paso con fecha, o lo marca como hecho (queda en el historial)."""
    conn = get_conn()
    cur = conn.cursor()
    if request.form.get("accion") == "hecho":
        cur.execute("SELECT proximo_paso FROM colegios WHERE id = %s", (colegio_id,))
        fila = cur.fetchone()
        if fila and fila["proximo_paso"]:
            registrar_interaccion(cur, colegio_id, "nota", f"✓ Hecho: {fila['proximo_paso']}")
        cur.execute("UPDATE colegios SET proximo_paso = NULL, proximo_paso_fecha = NULL WHERE id = %s", (colegio_id,))
        msg = "Paso marcado como hecho. Define el siguiente para que la relación no se enfríe."
    else:
        texto = (request.form.get("proximo_paso") or "").strip()[:300]
        fecha = fecha_o_none(request.form.get("proximo_paso_fecha"))
        if not texto or not fecha:
            cur.close()
            conn.close()
            return redirect(url_for("admin_colegio", colegio_id=colegio_id,
                                    msg="Próximo paso no guardado: escribe qué harás y elige una fecha."))
        cur.execute("UPDATE colegios SET proximo_paso = %s, proximo_paso_fecha = %s WHERE id = %s",
                    (texto, fecha, colegio_id))
        msg = "Próximo paso guardado."
    cur.close()
    conn.close()
    destino = volver_a(colegio_id)
    if destino.startswith(url_for("admin_colegio", colegio_id=colegio_id)):
        return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg=msg))
    return redirect(destino)


@app.route("/admin/colegios/<int:colegio_id>/interaccion", methods=["POST"])
@admin_login_required
def admin_interaccion(colegio_id):
    """Registrar: una reunión, llamada, correo, demostración o nota en el historial."""
    tipo = request.form.get("tipo") if request.form.get("tipo") in TIPO_INTERACCION_NOMBRE else "nota"
    nota = (request.form.get("nota") or "").strip()[:4000]
    fecha = fecha_o_none(request.form.get("fecha")) or date.today()
    if not nota:
        return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg="Escribe qué pasó para registrarlo."))
    conn = get_conn()
    cur = conn.cursor()
    registrar_interaccion(cur, colegio_id, tipo, nota, fecha)
    cur.close()
    conn.close()
    return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg="Registrado en el historial."))


@app.route("/admin/interacciones/<int:interaccion_id>/eliminar", methods=["POST"])
@admin_login_required
def admin_eliminar_interaccion(interaccion_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM interacciones WHERE id = %s RETURNING colegio_id", (interaccion_id,))
    fila = cur.fetchone()
    cur.close()
    conn.close()
    if not fila:
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("admin_colegio", colegio_id=fila["colegio_id"], msg="Registro eliminado del historial."))


@app.route("/admin/mensajes/<int:mensaje_id>/convertir", methods=["GET", "POST"])
@admin_login_required
def admin_convertir_mensaje(mensaje_id):
    """Convierte una solicitud de gaduai.cl en prospecto: crea la organización con el contacto,
    deja el mensaje en su historial y agenda responderlo hoy. Nada se copia a mano."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM mensajes_contacto WHERE id = %s", (mensaje_id,))
    m = cur.fetchone()
    if not m:
        cur.close()
        conn.close()
        return redirect(url_for("admin_hoy"))
    if m.get("colegio_id"):
        cur.close()
        conn.close()
        return redirect(url_for("admin_colegio", colegio_id=m["colegio_id"]))
    if request.method == "POST":
        nombre = (request.form.get("nombre") or "").strip()
        tipo = request.form.get("tipo") if request.form.get("tipo") in TIPO_NOMBRE else "colegio"
        if not nombre:
            cur.close()
            conn.close()
            return render_template("admin_convertir.html", m=m, error="Escribe el nombre de la organización.")
        cur.execute(
            """INSERT INTO colegios (nombre, comuna, tipo, etapa, contacto_nombre, contacto_cargo, contacto_correo,
                                     proximo_paso, proximo_paso_fecha)
               VALUES (%s, %s, %s, 'contacto', %s, %s, %s, %s, %s) RETURNING id""",
            (nombre, (request.form.get("comuna") or "").strip() or None, tipo, m["nombre"],
             (request.form.get("cargo") or "").strip() or None, m["correo"],
             "Responder la solicitud de gaduai.cl", date.today()),
        )
        colegio_id = cur.fetchone()["id"]
        registrar_interaccion(cur, colegio_id, "correo", f"Solicitud desde gaduai.cl:\n{m['mensaje']}",
                              a_fecha(m.get("creado_en")))
        cur.execute("UPDATE mensajes_contacto SET leido = true, colegio_id = %s WHERE id = %s", (colegio_id, mensaje_id))
        cur.close()
        conn.close()
        return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg="Prospecto creado. Tu próximo paso: responder hoy."))
    cur.close()
    conn.close()
    return render_template("admin_convertir.html", m=m)


# Resumen diario por correo (lo llama un Cron Job de Render a las 8:00 con X-Tasks-Secret).
@app.route("/tareas/resumen-diario", methods=["POST"])
def tarea_resumen_diario():
    secreto = os.environ.get("TASKS_SECRET")
    if not secreto or not hmac.compare_digest((request.headers.get("X-Tasks-Secret") or "").encode(), secreto.encode()):
        return jsonify({"error": "no_autorizado"}), 401
    conn = get_conn()
    cur = conn.cursor()
    r = resumen_crm(cur)
    cur.close()
    conn.close()

    def lineas(orgs, con_fecha=True):
        return "\n".join(
            f"  • {o['nombre']}: {o['proximo_paso']}" + (f" ({formato_fecha(o['proximo_paso_fecha'])})" if con_fecha else "")
            for o in orgs
        )
    partes = []
    if r["atrasados"]:
        partes.append("ATRASADOS\n" + lineas(r["atrasados"]))
    if r["de_hoy"]:
        partes.append("PARA HOY\n" + lineas(r["de_hoy"], con_fecha=False))
    if r["semana"]:
        partes.append("ESTA SEMANA\n" + lineas(r["semana"]))
    if r["sin_paso"]:
        partes.append("EN EL EMBUDO SIN PRÓXIMO PASO\n" + "\n".join(f"  • {o['nombre']}" for o in r["sin_paso"]))
    if r["renovaciones"]:
        partes.append("RENOVACIONES\n" + "\n".join(
            f"  • {o['nombre']}: {o['contrato'][0].lower()} ({formato_fecha(o['fecha_termino'])})" for o in r["renovaciones"]))
    if r["mensajes"]:
        partes.append(f"MENSAJES NUEVOS DE GADUAI.CL: {len(r['mensajes'])} sin responder")
    pendientes = len(r["atrasados"]) + len(r["de_hoy"])
    cuerpo = ("Buenos días. Esto es lo que tienes hoy en GADUAI:\n\n"
              + ("\n\n".join(partes) if partes else "Todo al día: no hay pasos pendientes ni renovaciones cercanas.")
              + f"\n\nClientes activos: {r['n_clientes']} · Ingreso mensual: {formato_clp(r['ingreso'])}"
              + f" · En el embudo: {r['n_embudo']} ({formato_clp(r['valor_embudo'])} al mes)"
              + f"\n\nAbrir el Centro de control: {PANEL_URL}")
    asunto = f"GADUAI · Hoy: {pendientes} pendiente{'s' if pendientes != 1 else ''}" + (
        f" ({len(r['atrasados'])} atrasado{'s' if len(r['atrasados']) != 1 else ''})" if r["atrasados"] else "")
    try:
        enviar_correo_admin(asunto, cuerpo)
    except Exception as e:
        app.logger.error(f"No se pudo enviar el resumen diario: {e}")
        return jsonify({"error": "no_enviado"}), 502
    return jsonify({"ok": True, "pendientes": pendientes})


@app.route("/admin/colegios/<int:colegio_id>/acceso/<producto>", methods=["POST"])
@admin_login_required
def admin_toggle_acceso(colegio_id, producto):
    if producto not in ("relacionai", "triage", "gaduai"):
        return redirect(url_for("admin_colegio", colegio_id=colegio_id))
    habilitado = request.form.get("habilitado") == "1"
    msg = "Guardado."

    conn = get_conn()
    cur = conn.cursor()
    if producto == "triage" and habilitado:
        # TRIAGE es un solo despliegue compartido: en vez de pedir una URL a mano, el propio
        # panel activa el colegio ahí (o reconoce el que ya existe) y arma el link directo a
        # su login — así el encargado nunca ve la pantalla pública de "crear colegio".
        cur.execute("SELECT nombre, comuna FROM colegios WHERE id = %s", (colegio_id,))
        colegio = cur.fetchone()
        try:
            activado = activar_colegio_en_triage(colegio["nombre"], colegio["comuna"])
        except TriageError as exc:
            cur.close()
            conn.close()
            return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg=f"No se pudo habilitar TRIAGE: {exc}"))
        url = activado["url"]
        if activado["master"]:
            msg = f"TRIAGE activado. Acceso máster: {activado['master']['correo']} / clave {activado['master']['clave']} (guárdala, no se muestra de nuevo)."
    else:
        url = request.form.get("url", "").strip() or None

    cur.execute(
        """INSERT INTO accesos (colegio_id, producto, habilitado, url) VALUES (%s, %s, %s, %s)
           ON CONFLICT (colegio_id, producto) DO UPDATE SET habilitado = EXCLUDED.habilitado, url = EXCLUDED.url""",
        (colegio_id, producto, habilitado, url),
    )
    cur.close()
    conn.close()
    return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg=msg))


@app.route("/admin/colegios/<int:colegio_id>/reset-master-triage", methods=["POST"])
@admin_login_required
def admin_reset_master_triage(colegio_id):
    """Genera una clave nueva para el usuario máster de este colegio en TRIAGE GADUAI —
    para cuando la clave mostrada al habilitar TRIAGE la primera vez se perdió. Opcionalmente
    también actualiza el correo de acceso, si el campo `correoNuevo` viene lleno."""
    correo_nuevo = (request.form.get("correoNuevo") or "").strip() or None
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT nombre FROM colegios WHERE id = %s", (colegio_id,))
    colegio = cur.fetchone()
    cur.close()
    conn.close()
    if not colegio:
        return redirect(url_for("admin_dashboard"))

    colegio_id_triage = slug_colegio(colegio["nombre"])
    try:
        master = resetear_master_en_triage(colegio_id_triage, correo_nuevo)
    except TriageError as exc:
        return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg=f"No se pudo resetear la clave: {exc}"))
    msg = f"Clave del máster reseteada. Acceso: {master['correo']} / clave {master['clave']} (guárdala, no se muestra de nuevo)."
    return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg=msg))


@app.route("/admin/colegios/<int:colegio_id>/codigo", methods=["POST"])
@admin_login_required
def admin_codigo_acceso(colegio_id):
    """Define, cambia o quita el código con que el personal entra desde gaduai.cl. Al
    cambiarlo, el código anterior deja de funcionar de inmediato."""
    codigo = normalizar_codigo(request.form.get("codigo"))
    if codigo and not CODIGO_RE.match(codigo):
        return redirect(url_for("admin_colegio", colegio_id=colegio_id,
                                msg="Código no guardado: usa entre 4 y 24 letras, números o guiones (sin espacios)."))
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE colegios SET codigo_acceso = %s WHERE id = %s", (codigo or None, colegio_id))
    except Exception:
        cur.close()
        conn.close()
        return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg="Ese código ya lo usa otro colegio. Elige otro."))
    cur.close()
    conn.close()
    msg = f"Código guardado: {codigo}." if codigo else "Código quitado: nadie puede entrar a este colegio desde gaduai.cl."
    return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg=msg))


@app.route("/admin/colegios/<int:colegio_id>/eliminar", methods=["POST"])
@admin_login_required
def admin_eliminar_colegio(colegio_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM colegios WHERE id = %s", (colegio_id,))
    cur.close()
    conn.close()
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
