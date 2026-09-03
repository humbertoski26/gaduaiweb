import os
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

from db import get_conn, init_db

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

PRODUCTOS = {
    "relacionai": {"nombre": "Relacionai", "descripcion": "Gestión de convivencia escolar y casos."},
    "triage": {"nombre": "TRIAGE GADUAI", "descripcion": "Timeline y triage de la gestión del colegio."},
}

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


@app.route("/admin")
@admin_login_required
def admin_dashboard():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM colegios ORDER BY nombre")
    colegios = cur.fetchall()
    cur.execute("SELECT * FROM accesos")
    accesos_por_colegio = {}
    for row in cur.fetchall():
        accesos_por_colegio.setdefault(row["colegio_id"], {})[row["producto"]] = row["habilitado"]
    cur.close()
    conn.close()

    for c in colegios:
        c["acc"] = accesos_por_colegio.get(c["id"], {})
    return render_template("admin_dashboard.html", colegios=colegios)


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
    url = request.form.get("url", "").strip() or None
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO accesos (colegio_id, producto, habilitado, url) VALUES (%s, %s, %s, %s)
           ON CONFLICT (colegio_id, producto) DO UPDATE SET habilitado = EXCLUDED.habilitado, url = EXCLUDED.url""",
        (colegio_id, producto, habilitado, url),
    )
    cur.close()
    conn.close()
    return redirect(url_for("admin_colegio", colegio_id=colegio_id, msg="Guardado."))


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
