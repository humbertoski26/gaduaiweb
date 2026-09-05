import json
import os
import re
import unicodedata
from functools import wraps
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_conn, init_db

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

PRODUCTOS = {
    "relacionai": {"nombre": "Relacionai", "descripcion": "Gestión de convivencia escolar y casos."},
    "triage": {"nombre": "TRIAGE GADUAI", "descripcion": "Timeline y triage de la gestión del colegio."},
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

# El botón de contacto vive en el sitio público (otro origen), así que ese único
# endpoint necesita CORS habilitado para poder recibir el POST desde gaduai.cl.
ALLOWED_ORIGINS = {"https://gaduai.cl", "https://www.gaduai.cl", "https://gaduai-web.onrender.com"}


@app.after_request
def add_cors_headers(resp):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

with app.app_context():
    init_db()


def colegio_login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("colegio_id"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def admin_login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*a, **kw)
    return wrapper


@app.route("/")
def index():
    if session.get("colegio_id"):
        return redirect(url_for("portal"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM usuarios_colegio WHERE email = %s", (email,))
        usuario = cur.fetchone()
        cur.close()
        conn.close()
        if usuario and check_password_hash(usuario["password_hash"], password):
            session["colegio_id"] = usuario["colegio_id"]
            return redirect(url_for("portal"))
        return render_template("login.html", error="Correo o clave incorrectos.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("colegio_id", None)
    return redirect(url_for("login"))


@app.route("/portal")
@colegio_login_required
def portal():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM colegios WHERE id = %s", (session["colegio_id"],))
    colegio = cur.fetchone()
    cur.execute("SELECT * FROM accesos WHERE colegio_id = %s", (session["colegio_id"],))
    accesos = {row["producto"]: row for row in cur.fetchall()}
    cur.close()
    conn.close()

    productos = []
    for clave, meta in PRODUCTOS.items():
        acc = accesos.get(clave)
        productos.append({
            "nombre": meta["nombre"],
            "descripcion": meta["descripcion"],
            "habilitado": bool(acc and acc["habilitado"]),
            "url": acc["url"] if acc else None,
        })
    # GADUAI (la plataforma completa) sigue en prototipo: nunca se ofrece como habilitable todavía.
    productos.append({
        "nombre": "GADUAI",
        "descripcion": "Sistema de inteligencia organizacional completo.",
        "habilitado": False,
        "url": None,
    })
    return render_template("portal.html", colegio=colegio, productos=productos)


# ---------- admin ----------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        if email == os.environ["ADMIN_EMAIL"].strip().lower() and password == os.environ["ADMIN_PASSWORD"]:
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        return render_template("admin_login.html", error="Correo o clave incorrectos.")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


# ---------- formulario de contacto público (llamado desde gaduai.cl) ----------

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


@app.route("/admin")
@admin_login_required
def admin_dashboard():
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
    return render_template("admin_dashboard.html", colegios=colegios, mensajes_no_leidos=mensajes_no_leidos)


@app.route("/admin/colegios/nuevo", methods=["GET", "POST"])
@admin_login_required
def admin_nuevo_colegio():
    if request.method == "POST":
        nombre = request.form["nombre"].strip()
        comuna = request.form.get("comuna", "").strip() or None
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO colegios (nombre, comuna) VALUES (%s, %s) RETURNING id",
                (nombre, comuna),
            )
            colegio_id = cur.fetchone()["id"]
            cur.execute(
                "INSERT INTO usuarios_colegio (colegio_id, email, password_hash) VALUES (%s, %s, %s)",
                (colegio_id, email, generate_password_hash(password)),
            )
        except Exception:
            cur.close()
            conn.close()
            return render_template("admin_nuevo_colegio.html", error="No se pudo crear (¿correo ya usado?).")
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
    cur.execute("SELECT * FROM usuarios_colegio WHERE colegio_id = %s", (colegio_id,))
    usuario = cur.fetchone()
    cur.execute("SELECT * FROM accesos WHERE colegio_id = %s", (colegio_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()

    acc = {}
    for row in rows:
        acc[row["producto"]] = row["habilitado"]
        acc[f"{row['producto']}_url"] = row["url"]

    return render_template("admin_colegio.html", colegio=colegio, usuario=usuario, acc=acc, msg=request.args.get("msg"))


@app.route("/admin/colegios/<int:colegio_id>/acceso/<producto>", methods=["POST"])
@admin_login_required
def admin_toggle_acceso(colegio_id, producto):
    if producto not in ("relacionai", "triage"):
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


@app.route("/admin/colegios/<int:colegio_id>/clave", methods=["POST"])
@admin_login_required
def admin_reset_password(colegio_id):
    password = request.form["password"]
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE usuarios_colegio SET password_hash = %s WHERE colegio_id = %s",
        (generate_password_hash(password), colegio_id),
    )
    cur.close()
    conn.close()
    return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg="Clave actualizada."))


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
