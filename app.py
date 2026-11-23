"""PROA Valme. Aplicación WSGI con SQLite y cuentas provisionadas por CLI."""

import argparse
import csv
import getpass
import hashlib
import hmac
import html
import io
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode, urlsplit
from wsgiref.simple_server import make_server

DB = os.environ.get("PROAVALME_DB", "proavalme.sqlite3")
SECURE = os.environ.get("PROAVALME_HTTPS") == "1"
TTL = 8 * 3600
MAX_BODY = 8_000_000
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 email TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL, temporary INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
 token TEXT PRIMARY KEY, email TEXT NOT NULL REFERENCES users(email), expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS attempts (scope TEXT NOT NULL, at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS attempts_scope ON attempts(scope,at);
CREATE TABLE IF NOT EXISTS batches (
 id INTEGER PRIMARY KEY, email TEXT NOT NULL, filename TEXT NOT NULL, at TEXT DEFAULT CURRENT_TIMESTAMP,
 periods TEXT NOT NULL, rows_count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS records (
 period TEXT NOT NULL, metric TEXT NOT NULL, scope TEXT NOT NULL, category TEXT NOT NULL,
 item TEXT NOT NULL, unit TEXT NOT NULL, value REAL NOT NULL,
 batch INTEGER NOT NULL REFERENCES batches(id), active INTEGER NOT NULL DEFAULT 1);
CREATE INDEX IF NOT EXISTS records_active ON records(active, metric, period);
CREATE TABLE IF NOT EXISTS previews (
 id TEXT PRIMARY KEY, email TEXT NOT NULL, filename TEXT NOT NULL, payload TEXT NOT NULL,
 revision INTEGER NOT NULL, expires INTEGER NOT NULL);
"""
FIELDS = ("periodo", "indicador", "ambito", "grupo", "elemento", "unidad", "valor")
METRICS = {"consumo": "Consumo", "gasto": "Gasto", "microbiologia": "Microbiología"}
UNITS = {"consumo": {"DDD/1.000 estancias"}, "gasto": {"EUR"}}
PERIOD = re.compile(r"20[0-9]{2}(?:-T[1-4])?")
SESSION_NAME = "proavalme"
DUMMY = "0"*32 + ":" + "0"*128


@contextmanager
def database():
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA foreign_keys = ON")
        with db:
            yield db
    finally:
        db.close()


def init():
    with database() as db:
        db.executescript(SCHEMA)


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    key = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=1,
                         maxmem=64*1024*1024)
    return salt + ":" + key.hex()


def verify(password, expected):
    return hmac.compare_digest(password_hash(password, expected.split(":")[0]), expected)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def csrf(token):
    return hmac.new(bytes.fromhex(token), b"proavalme-csrf", hashlib.sha256).hexdigest()


def provision(email, role, password):
    email = email.strip().casefold()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(password) < 12:
        raise ValueError("Correo válido y contraseña de al menos 12 caracteres.")
    with database() as db:
        db.execute("INSERT INTO users VALUES (?,?,?,1)", (email, password_hash(password), role))


def escape(value):
    return html.escape(str(value), quote=True)


def cookie(value, age):
    attributes = "; Secure" if SECURE else ""
    return f"{SESSION_NAME}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{attributes}"


def reply(start, status, body, *, content="text/html; charset=utf-8", extra=()):
    start(status, [
        ("Content-Type", content), ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
        ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "
         "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
        *extra,
    ])
    return [body.encode() if isinstance(body, str) else body]


def redirect(start, path, extra=()):
    return reply(start, "303 See Other", "", extra=[("Location", path), *extra])


def field(name, value):
    return f'<input type="hidden" name="{escape(name)}" value="{escape(value)}">'


def layout(title, body, user=None, token=None):
    nav = ""
    if user:
        nav = '<a href="/">Panel</a> <a href="/history">Histórico</a> <a href="/password">Contraseña</a>'
        if user["role"] == "editor":
            nav += ' <a href="/import">Cargar datos</a>'
        nav += ('<form method="post" action="/logout">' + field("csrf", csrf(token))
                + '<button>Cerrar sesión</button></form>')
    return f"""<!doctype html><html lang="es"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)} · PROA Valme</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#f1f6f7;color:#19343c;font:16px system-ui}}
header{{background:#113a45;color:#fff;padding:1.5rem max(5vw,1rem)}}header strong{{font-size:1.45rem}}
nav{{display:flex;align-items:center;flex-wrap:wrap;gap:1rem;margin-top:1rem}}nav a{{color:#fff}}
main{{max-width:1160px;margin:auto;padding:1.4rem}}section{{padding:1.2rem;background:#fff;border:1px solid #d5e2e5;border-radius:.75rem;margin-bottom:1rem}}
label{{display:inline-grid;gap:.35rem;margin:.35rem .55rem .35rem 0}}button,input,select{{font:inherit;padding:.5rem}}
button,.action{{background:#08665b;color:#fff;border:0;border-radius:.35rem;padding:.6rem .85rem;text-decoration:none;cursor:pointer}}
a{{color:#08665b}}.scroll{{overflow:auto}}table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;padding:.55rem;border-bottom:1px solid #d5e2e5}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap}}.cards div{{flex:1;min-width:150px;padding:1rem;background:#e9f4f1;border-radius:.5rem}}.cards strong{{display:block;font-size:1.4rem}}
.line{{display:grid;grid-template-columns:minmax(100px,1fr) 3fr minmax(85px,1fr);gap:.65rem;align-items:center;margin:.4rem 0}}
meter{{width:100%;height:1.4rem}}footer{{max-width:1160px;margin:auto;padding:0 1.4rem 1.4rem;color:#42616a}}.alert{{border-left:4px solid #b77512;padding:.65rem;background:#fff6e6}}
@media print{{header,footer,.actions,nav,form{{display:none!important}}body{{background:white;color:black}}main,section{{padding:0;border:0}}tr,.line{{break-inside:avoid}}thead{{display:table-header-group}}}}
</style><header><strong>PROA Valme</strong><nav>{nav}</nav></header>
<main><h1>{escape(title)}</h1>{body}</main><footer>Hospital Universitario Virgen de Valme · Desarrollo Ramón Morillo</footer></html>"""


def parse_upload(name, raw):
    name = name.lower()
    if name.endswith(".csv"):
        text = raw.decode("utf-8-sig")
        source = csv.reader(io.StringIO(text), delimiter=";" if ";" in text.splitlines()[0] else ",")
        return normalize(source)
    if name.endswith(".xlsx"):
        from zipfile import ZipFile
        from openpyxl import load_workbook
        with ZipFile(io.BytesIO(raw)) as archive:
            if sum(info.file_size for info in archive.infolist()) > 30_000_000:
                raise ValueError("El libro descomprimido excede el límite.")
        book = load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
        try:
            sheet = book["Datos"] if "Datos" in book.sheetnames else book.active
            return normalize(sheet.iter_rows(max_col=8, values_only=True))
        finally:
            book.close()
    raise ValueError("Usa CSV UTF-8 o XLSX con la estructura de la plantilla.")


def clean(value):
    return "" if value is None else str(value).strip()


def normalize(source):
    import math
    iterator = iter(source)
    header = tuple(clean(x).casefold() for x in next(iterator, ()))
    if header[:7] != FIELDS or any(header[7:]):
        raise ValueError("Los encabezados deben coincidir con la plantilla.")
    prepared = []
    keys = set()
    for index, source_row in enumerate(iterator, 2):
        if index > 10002:
            raise ValueError("El fichero supera el límite de 10.000 filas.")
        row = [clean(x) for x in source_row]
        if not any(row):
            continue
        if len(row) < 7 or any(row[7:]):
            raise ValueError(f"Fila {index}: se esperan siete columnas.")
        period, metric, scope, group, item, unit, raw_value = row[:7]
        if (not PERIOD.fullmatch(period) or metric not in METRICS or not all((scope, group, item, unit))
                or unit not in UNITS.get(metric, {unit}) or any(len(x) > 160 for x in row[:7])):
            raise ValueError(f"Fila {index}: revisa el periodo, indicador, ámbito, grupo, elemento o unidad.")
        try:
            value = float(raw_value.replace(",", "."))
        except ValueError:
            raise ValueError(f"Fila {index}: falta un valor numérico válido.") from None
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"Fila {index}: el valor debe ser finito y no negativo.")
        key = tuple(x.casefold() for x in (period, metric, scope, group, item))
        if key in keys:
            raise ValueError(f"Fila {index}: indicador, ámbito y elemento duplicados en el periodo.")
        keys.add(key)
        if any(x.startswith(("=", "+", "-", "@")) for x in (scope, group, item, unit)):
            raise ValueError(f"Fila {index}: los campos de texto deben comenzar con un nombre.")
        prepared.append((period, metric, scope, group, item, unit, value))
    if not prepared:
        raise ValueError("El fichero está vacío.")
    return prepared


def csv_response(start, rows, name):
    def cell(value):
        if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
            return "'" + value
        return value
    out = io.StringIO()
    writer = csv.writer(out, delimiter=";")
    writer.writerow(FIELDS)
    writer.writerows([cell(x) for x in tuple(row)[:7]] for row in rows)
    return reply(start, "200 OK", "\ufeff" + out.getvalue(), content="text/csv; charset=utf-8",
                 extra=[("Content-Disposition", f'attachment; filename="{name}"')])


def num(value):
    return f"{value:,.4f}".rstrip("0").rstrip(".").replace(",", "_").replace(".", ",").replace("_", ".")


def table(rows, headers=FIELDS):
    heading = "".join(f'<th scope="col">{escape(column)}</th>' for column in headers)
    body = "".join("<tr>" + "".join(f"<td>{escape(num(x) if isinstance(x,float) else x)}</td>"
                                  for x in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{heading}</tr></thead><tbody>{body}</tbody></table></div>'


def form_body(env):
    size = int(env.get("CONTENT_LENGTH") or "0")
    if not 0 <= size <= MAX_BODY:
        raise ValueError("El fichero supera el límite de carga.")
    return env["wsgi.input"].read(size)


def values(raw):
    return {key: vals[-1] for key, vals in parse_qs(raw, keep_blank_values=True).items()}


def multipart(env, payload):
    from email.parser import BytesParser
    from email.policy import default
    content_type = env.get("CONTENT_TYPE", "")
    if not content_type.startswith("multipart/form-data;") or "\r" in content_type or "\n" in content_type:
        raise ValueError("Formato de carga inválido.")
    message = BytesParser(policy=default).parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + payload)
    return {p.get_param("name", header="content-disposition"): p for p in message.iter_parts()}


def session(db, env):
    raw = SimpleCookie(env.get("HTTP_COOKIE", "")).get(SESSION_NAME)
    token = raw.value if raw else ""
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        return None, ""
    user = db.execute("SELECT u.* FROM users u JOIN sessions s ON u.email=s.email "
                      "WHERE s.token=? AND s.expires>?", (token_hash(token), int(time.time()))).fetchone()
    return user, token


def login_form(error=""):
    alert = f'<p class="alert">{escape(error)}</p>' if error else ""
    return alert + """<section><form method="post">
<label>Correo profesional <input name="email" type="email" autocomplete="username" required></label>
<label>Contraseña <input name="password" type="password" autocomplete="current-password" required></label>
<button>Entrar</button></form></section>"""


def login(db, env, start):
    origin = env.get("HTTP_ORIGIN", "")
    if origin and urlsplit(origin).netloc != env.get("HTTP_HOST"):
        return reply(start, "403 Forbidden", "Origen de acceso inválido.")
    if env.get("HTTP_SEC_FETCH_SITE") == "cross-site":
        return reply(start, "403 Forbidden", "Origen de acceso inválido.")
    params = values(form_body(env).decode())
    email = params.get("email", "").strip().casefold()[:254]
    ip = env.get("REMOTE_ADDR", "")
    scopes = ("ip:" + ip, "email:" + email)
    now = int(time.time())
    db.execute("BEGIN IMMEDIATE")
    db.execute("DELETE FROM attempts WHERE at<?", (now-900,))
    totals = [db.execute("SELECT count(*) FROM attempts WHERE scope=?", (scope,)).fetchone()[0]
              for scope in scopes]
    if totals[0] >= 45 or totals[1] >= 8:
        return reply(start, "429 Too Many Requests", layout("Acceso privado", login_form("Espera 15 minutos antes de volver a intentarlo.")))
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    supplied = params.get("password", "")
    valid = len(supplied) <= 512 and verify(supplied, user["password"] if user else DUMMY)
    if not user or not valid:
        db.executemany("INSERT INTO attempts VALUES (?,?)", ((scope, now) for scope in scopes))
        return reply(start, "401 Unauthorized", layout("Acceso privado", login_form("Correo o contraseña incorrectos.")))
    db.execute("DELETE FROM attempts WHERE scope=?", (scopes[1],))
    db.execute("DELETE FROM sessions WHERE expires<=?", (now,))
    token = secrets.token_hex(32)
    db.execute("INSERT INTO sessions VALUES (?,?,?)", (token_hash(token), email, now+TTL))
    return redirect(start, "/password" if user["temporary"] else "/", [("Set-Cookie", cookie(token, TTL))])

def update_password(db, user, token, params, start):
    new = params.get("new", "")
    old = params.get("old", "")
    if (not 14 <= len(new) <= 512 or len(old) > 512 or new == old
            or new != params.get("repeat") or not verify(old, user["password"])):
        raise ValueError("Comprueba la contraseña actual y elige una nueva de al menos 14 caracteres.")
    db.execute("UPDATE users SET password=?, temporary=0 WHERE email=?", (password_hash(new), user["email"]))
    db.execute("DELETE FROM sessions WHERE email=?", (user["email"],))
    replacement = secrets.token_hex(32)
    db.execute("INSERT INTO sessions VALUES (?,?,?)", (token_hash(replacement), user["email"], int(time.time())+TTL))
    return redirect(start, "/", [("Set-Cookie", cookie(replacement, TTL))])


def password_form(token, temporary):
    message = "<p>Elige tu contraseña personal antes de acceder al panel.</p>" if temporary else ""
    return message + '<section><form method="post">' + field("csrf", csrf(token)) + """
<label>Contraseña actual <input type="password" name="old" autocomplete="current-password" required></label>
<label>Nueva contraseña <input type="password" name="new" minlength="14" autocomplete="new-password" required></label>
<label>Repite la nueva contraseña <input type="password" name="repeat" minlength="14" autocomplete="new-password" required></label>
<button>Guardar contraseña</button></form></section>"""


def revision(db):
    return db.execute("SELECT coalesce(max(id),0) FROM batches").fetchone()[0]


def upload_form(token):
    return '<section><p>Importa datos agregados con el formato de la plantilla. ' \
           'Usa un fichero completo para cada ámbito y periodo que quieras sustituir.</p>' \
           '<p><a href="/template">Descargar plantilla de prueba</a></p>' \
           '<form method="post" enctype="multipart/form-data">' + field("csrf", csrf(token)) + """
<label>Fichero CSV o XLSX <input name="upload" type="file" accept=".csv,.xlsx" required></label>
<button>Revisar antes de incorporar</button></form></section>"""


def scopes(rows):
    return sorted({(row[0],row[1],row[2]) for row in rows})


def active_count(db, keys):
    return sum(db.execute("SELECT count(*) FROM records WHERE active=1 AND period=? AND metric=? AND scope=?",
                          key).fetchone()[0] for key in keys)


def preview(db, start, user, token, parts):
    import json
    uploaded = parts.get("upload")
    filename = (uploaded.get_filename() or "")[:180] if uploaded else ""
    if not filename:
        raise ValueError("Selecciona un fichero.")
    try:
        rows = parse_upload(filename, uploaded.get_payload(decode=True))
    except (UnicodeError, csv.Error, IndexError, OSError, KeyError):
        raise ValueError("El fichero no se ha podido leer. Comprueba el formato.") from None
    except Exception as error:
        if isinstance(error, (ValueError, ImportError)):
            raise
        if error.__class__.__module__.startswith(("zipfile", "openpyxl", "xml", "lxml")):
            raise ValueError("El libro Excel no es válido.") from None
        raise
    affected = scopes(rows)
    replacements = active_count(db, affected)
    draft = uuid.uuid4().hex
    now = int(time.time())
    db.execute("DELETE FROM previews WHERE expires<=? OR email=?", (now, user["email"]))
    db.execute("INSERT INTO previews VALUES (?,?,?,?,?,?)",
               (draft,user["email"],filename,json.dumps(rows),revision(db),now+900))
    confirm = (f'<p class="alert">Se retirarán {replacements} filas vigentes de los ámbitos, indicadores '
               'y periodos incluidos. Las versiones anteriores quedarán en el histórico.</p>'
               '<label><input type="checkbox" name="replace" value="1" required> Confirmo la sustitución</label>'
               if replacements else "")
    body = (f"<section><p>{len(rows)} filas de <strong>{escape(filename)}</strong>. "
            "Se muestran las primeras 12.</p>" + table(rows[:12]) + "</section>"
            '<section><form method="post" action="/confirm">' + field("csrf",csrf(token))
            + field("draft",draft) + confirm + '<button>Confirmar carga</button></form></section>')
    return reply(start, "200 OK", layout("Revisar carga", body, user, token))


def commit_upload(db, start, user, params):
    import json
    db.execute("BEGIN IMMEDIATE")
    draft = db.execute("SELECT * FROM previews WHERE id=? AND email=? AND expires>?",
                       (params.get("draft",""),user["email"],int(time.time()))).fetchone()
    if not draft or draft["revision"] != revision(db):
        raise ValueError("La revisión caducó o el histórico cambió. Vuelve a cargar el fichero.")
    rows = json.loads(draft["payload"])
    affected = scopes(rows)
    if active_count(db, affected) and params.get("replace") != "1":
        raise ValueError("Confirma la sustitución de las filas anteriores.")
    batch = db.execute("INSERT INTO batches(email,filename,periods,rows_count) VALUES(?,?,?,?)",
                       (user["email"],draft["filename"],", ".join(sorted({r[0] for r in rows})),len(rows))).lastrowid
    db.executemany("UPDATE records SET active=0 WHERE active=1 AND period=? AND metric=? AND scope=?", affected)
    db.executemany("INSERT INTO records VALUES(?,?,?,?,?,?,?,?,1)", ((*r,batch) for r in rows))
    db.execute("DELETE FROM previews WHERE id=?", (draft["id"],))
    return redirect(start, "/history")


def select(name, label, options, selected):
    choices = "".join(f'<option value="{escape(value)}" {"selected" if value == selected else ""}>'
                      f'{escape(title)}</option>' for value,title in options)
    return f'<label>{escape(label)} <select name="{name}">{choices}</select></label>'


def dashboard(db, start, user, token, path, params):
    data = [tuple(row) for row in db.execute(
        "SELECT period,metric,scope,category,item,unit,value,b.filename FROM records r "
        "JOIN batches b ON r.batch=b.id WHERE active=1 ORDER BY period,metric,scope,category,item")]
    filters = [
        ("metric","Indicador",1,list(METRICS.items())),
        ("scope","Ámbito o GFH",2,sorted({(r[2],r[2]) for r in data})),
        ("group","Grupo",3,sorted({(r[3],r[3]) for r in data})),
        ("item","Principio activo o indicador",4,sorted({(r[4],r[4]) for r in data})),
    ]
    selected = {key:params.get(key,"") for key,_,_,_ in filters}
    frequency = params.get("frequency","")
    date_options = [(p,p) for p in sorted({r[0] for r in data})]
    for key in ("from","to"):
        selected[key] = params.get(key,"")
    selected["frequency"] = frequency
    result = [r for r in data if all(not selected[k] or r[i] == selected[k] for k,_,i,_ in filters)
              and (not selected["from"] or r[0]>=selected["from"])
              and (not selected["to"] or r[0]<=selected["to"])
              and (not frequency or len(r[0]) == {"quarter":7,"year":4}.get(frequency))]
    if path == "/export":
        return csv_response(start,result,"proavalme.csv")
    is_report = path == "/report"
    query = urlencode(selected)
    controls = ""
    if not is_report:
        controls = ''.join(select(k,label,[("","Todos"),*options],selected[k]) for k,label,_,options in filters)
        controls += select("from","Desde",[("","Inicio"),*date_options],selected["from"])
        controls += select("to","Hasta",[("","Final"),*date_options],selected["to"])
        controls += select("frequency","Periodicidad",[("","Todas"),("quarter","Trimestral"),("year","Anual")],frequency)
        controls = f'<section><form method="get">{controls}<button>Aplicar filtros</button></form></section>'
    summary = '<section><div class="cards">' + ''.join(
        f'<div>{escape(label)}<strong>{n}</strong></div>' for label,n in
        [("Periodos",len({r[0] for r in result})),("Indicadores disponibles",len({r[1] for r in result})),
        ("Registros",len(result))]) + '</div></section>'
    links = (f'<p class="actions"><a class="action" href="/report">Informe general</a> '
             f'<a class="action" href="/report?{escape(query)}">Informe personalizado</a> '
             f'<a class="action" href="/export?{escape(query)}">Exportar CSV</a></p>')
    if is_report:
        links = '<p class="actions">Pulsa Ctrl+P y elige «Guardar como PDF» o tu impresora.</p>'
        labels = {"metric":"Indicador","scope":"Ámbito","group":"Grupo","item":"Elemento",
                  "from":"Desde","to":"Hasta","frequency":"Periodicidad"}
        description = ", ".join(f"{labels[k]}: {METRICS.get(v, {'quarter':'Trimestral','year':'Anual'}.get(v,v))}"
                               for k,v in selected.items() if v) or "Todos los registros vigentes"
        summary = f'<p>{escape(description)}</p>' + summary
    series = {}
    for period,metric,scope,group,item,unit,value,_ in result:
        series.setdefault((metric,scope,group,item,unit,len(period)),[]).append((period,value))
    charts = []
    for (_,scope,group,item,unit,_), points in sorted(series.items(),key=lambda pair:(-len(pair[1]),pair[0]))[:8]:
        if len(points) < 2:
            continue
        largest = max(1,max(value for _,value in points))
        lines = "".join(f'<div class="line"><span>{period}</span><meter min="0" max="{largest}" '
                        f'value="{value}" aria-label="{period}"></meter><span>{num(value)}</span></div>'
                        for period,value in points)
        charts.append(f'<section><h2>{escape(item)}</h2><p>{escape(scope)} · {escape(group)} · '
                      f'{escape(unit)}</p>{lines}</section>')
    detail = table(((p,METRICS[m],s,g,i,u,v,source) for p,m,s,g,i,u,v,source in result),
                   ("Periodo","Indicador","Ámbito","Grupo","Elemento","Unidad","Valor","Fuente"))
    if not result:
        detail = "<p>No hay registros para esta selección.</p>"
    return reply(start,"200 OK",layout("Informe personalizado" if is_report and any(selected.values()) else
                 "Informe general" if is_report else "Panel de antimicrobianos",
                 controls + links + summary + "".join(charts) + '<section><h2>Detalle</h2>' + detail + '</section>',user,token))


def dispatch(db, env, start):
    method = env["REQUEST_METHOD"]
    path = env["PATH_INFO"]
    user, token = session(db,env)
    if method not in {"GET","POST"}:
        return reply(start,"405 Method Not Allowed","Método no permitido.")
    if path == "/login":
        if method == "POST":
            return login(db,env,start)
        return reply(start,"200 OK",layout("Acceso privado",login_form()))
    if not user:
        return redirect(start,"/login")
    params = values(env.get("QUERY_STRING",""))
    if method == "POST":
        raw = form_body(env)
        parts = multipart(env,raw) if path == "/import" else {}
        params = ({k:p.get_content().strip() for k,p in parts.items() if k=="csrf"}
                  if path=="/import" else values(raw.decode()))
        if not hmac.compare_digest(params.get("csrf",""),csrf(token)):
            return reply(start,"403 Forbidden","Solicitud inválida.")
        if path == "/logout":
            db.execute("DELETE FROM sessions WHERE token=?", (token_hash(token),))
            return redirect(start,"/login",[("Set-Cookie",cookie("",0))])
    if path == "/password":
        if method == "POST":
            return update_password(db,user,token,params,start)
        return reply(start,"200 OK",layout("Cambiar contraseña",password_form(token,user["temporary"]),user,token))
    if user["temporary"]:
        return redirect(start,"/password")
    if path in {"/import","/confirm"} and user["role"] != "editor":
        return reply(start,"403 Forbidden",layout("Permiso de consulta","<p>Tu cuenta puede consultar y exportar informes.</p>",user,token))
    if method == "POST":
        if path == "/import":
            return preview(db,start,user,token,parts)
        if path == "/confirm":
            return commit_upload(db,start,user,params)
    if method == "GET":
        if path in {"/","/report","/export"}:
            return dashboard(db,start,user,token,path,params)
        if path == "/import":
            return reply(start,"200 OK",layout("Cargar datos",upload_form(token),user,token))
        if path == "/template":
            return csv_response(start,[
                ("2025-T1","consumo","Hospital","Carbapenémicos","Meropenem","DDD/1.000 estancias",20.2),
                ("2025-T2","consumo","Hospital","Carbapenémicos","Meropenem","DDD/1.000 estancias",17.9),
                ("2025-T1","gasto","Ingresados","Total","Antimicrobianos","EUR",1234),
                ("2025-T2","microbiologia","Hospital","Densidad","Indicador ficticio","Unidad de prueba",0.2),
            ],"plantilla-proavalme-ficticia.csv")
        if path == "/batch":
            batch = params.get("id","")
            if not re.fullmatch(r"[1-9][0-9]{0,14}",batch):
                return reply(start,"404 Not Found","Carga no encontrada.")
            rows = list(db.execute("SELECT period,metric,scope,category,item,unit,value "
                                   "FROM records WHERE batch=? ORDER BY period,metric,scope,item",(batch,)))
            if not rows:
                return reply(start,"404 Not Found","Carga no encontrada.")
            return csv_response(start,rows,f"proavalme-carga-{batch}.csv")
        if path == "/history":
            rows = db.execute("SELECT id,at,email,filename,periods,rows_count FROM batches ORDER BY id DESC")
            return reply(start,"200 OK",layout("Histórico de cargas",'<section>'+table(rows,
                         ("Carga","Fecha UTC","Cuenta","Fichero","Periodos","Filas"))
                         + '<h2>Descargar versiones por carga</h2><ul>'
                         + ''.join(f'<li><a href="/batch?id={row[0]}">Carga {row[0]}</a></li>'
                                   for row in db.execute("SELECT id FROM batches ORDER BY id DESC"))
                         + '</ul></section>',user,token))
    return reply(start,"404 Not Found","Página no encontrada.")


def application(env,start):
    try:
        with database() as db:
            return dispatch(db,env,start)
    except (ValueError,UnicodeError) as error:
        return reply(start,"400 Bad Request",layout("Revisar solicitud",
                     f'<p class="alert">{escape(error)}</p><a href="/">Volver al panel</a>'))
    except ImportError:
        return reply(start,"503 Service Unavailable",layout("Importación Excel no disponible",
                     '<p>El servidor necesita openpyxl. Puedes usar CSV.</p>'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command",required=True)
    commands.add_parser("init")
    user = commands.add_parser("add-user")
    user.add_argument("email")
    user.add_argument("role",choices=("editor","reader"))
    server = commands.add_parser("serve")
    server.add_argument("--port",type=int,default=8080)
    args = parser.parse_args()
    init()
    if args.command == "add-user":
        password = getpass.getpass("Contraseña temporal: ")
        try:
            provision(args.email,args.role,password)
        except (ValueError,sqlite3.IntegrityError) as error:
            raise SystemExit(f"No se ha creado la cuenta: {error}") from None
    if args.command == "serve":
        with make_server("127.0.0.1",args.port,application) as httpd:
            print(f"PROA Valme en http://127.0.0.1:{args.port}",flush=True)
            httpd.serve_forever()


if __name__ == "__main__":
    main()
