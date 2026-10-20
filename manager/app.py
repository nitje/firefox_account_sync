
"""Standalone Manager 0.6.0: users, backups and offline restore orchestration."""
import base64
import hashlib
import hmac
import html
import json
import re
from urllib.parse import urlsplit, parse_qs
import os
import time
import secrets
import registration
import account_access
from datetime import datetime, timezone
import pymysql
import urllib.request
import urllib.error
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADMIN_USER = os.environ["ADMIN_USER"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
SYNC_HEALTH_URL = os.environ["SYNC_HEALTH_URL"]
PUBLIC_SYNC = os.environ["SYNC_PUBLIC_URL"]
FXA_CONTENT = os.environ["FXA_CONTENT_URL"]
FXA_OAUTH = os.environ["FXA_OAUTH_URL"]
FXA_DISCOVERY_HEALTH_URL = os.environ.get("FXA_DISCOVERY_HEALTH_URL", "")
FXA_AUTH_HEALTH_URL = os.environ.get("FXA_AUTH_HEALTH_URL", "")
_configured_public = os.environ.get("MANAGER_PUBLIC_URL", "").strip()
# Standarddomain ableiten, wenn .env noch keinen expliziten Wert enthaelt.
_fxa_host = urlsplit(FXA_CONTENT).hostname or ""
MANAGER_PUBLIC = (_configured_public or
                  ("https://admin." + _fxa_host[len("accounts."):] if
                   _fxa_host.startswith("accounts.") else ""))
SALT = os.urandom(24)
CSRF = secrets.token_urlsafe(32)
HASH = hashlib.pbkdf2_hmac("sha256", ADMIN_PASSWORD.encode(), SALT, 260000)
# Exakt dieselbe Ableitung wie manager/grant-readonly.sh: ADMIN_PASSWORD
# ist bereits fuer die Manager-Anmeldung vorhanden. Keine zweite, separate
# Umgebungsvariable, kein neues Secret und keine Aenderung an SQL-Grants.
RO_PASSWORD = hashlib.sha256(b"fxa-manager-ro-v1\x00" + ADMIN_PASSWORD.encode()).hexdigest()
# Administrationspasswort nicht länger als Klartext im Python-Global behalten.
del ADMIN_PASSWORD
RO_USER = os.environ.get("MANAGER_DB_USER", "fxa_manager_ro")
RO_HOST = os.environ.get("FXA_DB_HOST", "fxa-db")

# Internal backup admin authentication. ADMIN_PASSWORD is already present in .env.
# No shared writable backups volume is mounted in the unprivileged manager.
BACKUP_AGENT_URL = os.environ.get("BACKUP_AGENT_URL", "http://backup-admin:8091").rstrip("/")
BACKUP_SIGNING_KEY = hashlib.sha256(b"fxa-backup-management-v1\x00" +
                                     os.environ["ADMIN_PASSWORD"].encode()).digest()
BACKUP_NAME = re.compile(r"^backup-[0-9]{8}T[0-9]{6}Z(?:-[1-9][0-9]*)?$")
BACKUP_CONFIRMATIONS = {}
BACKUP_LOCK = threading.RLock()
BACKUP_JS = ("document.getElementById('toggle-backups').addEventListener('change', "
             "function(){document.querySelectorAll('input[name=\"backup\"]').forEach("
             "el=>el.checked=this.checked);});")
BACKUP_JS_HASH = base64.b64encode(hashlib.sha256(BACKUP_JS.encode()).digest()).decode()

# Restore agent is internal-only and uses a separate HMAC derivation from the same
# existing ADMIN_PASSWORD. The manager never receives DB credentials or RW volume mounts.
RESTORE_AGENT_URL = os.environ.get("RESTORE_AGENT_URL", "http://restore-admin:8092").rstrip("/")
RESTORE_SIGNING_KEY = hashlib.sha256(b"fxa-restore-management-v1\x00" +
                                      os.environ["ADMIN_PASSWORD"].encode()).digest()
RESTORE_CONFIRMATIONS = {}
RESTORE_LOCK = threading.RLock()


def backup_agent(path, payload=None):
    """Authenticated private HTTP call; no backup credentials or file contents in browser."""
    method = "POST" if payload is not None else "GET"
    data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
    moment = str(int(time.time()))
    message = method.encode() + b"\n" + path.encode() + b"\n" + moment.encode() + b"\n" + data
    signature = hmac.new(BACKUP_SIGNING_KEY, message, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        BACKUP_AGENT_URL + path, data=data if payload is not None else None, method=method,
        headers={"X-Backup-Timestamp": moment, "X-Backup-Signature": signature,
                 "Content-Type": "application/json" if payload is not None else "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            result = json.load(response)
        if not isinstance(result, dict):
            raise ValueError("Ungueltige Backup-Agent-Antwort")
        return result
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        # Do not reveal URLs containing secrets or file contents.
        raise OSError("Backup-Verwaltung derzeit nicht erreichbar (" + type(exc).__name__ + ")") from exc


def backup_inventory():
    result = backup_agent("/list")
    names = [entry.get("name") for entry in result.get("backups", [])]
    if len(names) != len(set(names)) or any(not isinstance(n, str) or not BACKUP_NAME.fullmatch(n) for n in names):
        raise OSError("Ungueltige Sicherungsliste")
    return result["backups"]


def backup_confirmation_create(names):
    # In-memory single-use confirmation snapshot. A later backup is never
    # accidentally included when user chose ALL on a previous page.
    if not names or len(names) > 2000 or any(not BACKUP_NAME.fullmatch(n) for n in names):
        raise ValueError("Keine oder zu viele Sicherungen ausgewaehlt")
    token = secrets.token_urlsafe(32)
    now = time.time()
    with BACKUP_LOCK:
        for key, item in list(BACKUP_CONFIRMATIONS.items()):
            if item[0] < now:
                BACKUP_CONFIRMATIONS.pop(key, None)
        BACKUP_CONFIRMATIONS[token] = (now + 600, tuple(names))
    return token


def backup_confirmation_take(token):
    with BACKUP_LOCK:
        record = BACKUP_CONFIRMATIONS.pop(token, None)
    if record is None or record[0] < time.time():
        raise ValueError("Bestaetigung abgelaufen oder bereits verwendet")
    return list(record[1])


def restore_agent(path, payload=None, timeout=30):
    """Authenticated request to the internal restore coordinator."""
    method = "POST" if payload is not None else "GET"
    data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
    moment = str(int(time.time()))
    message = method.encode() + b"\n" + path.encode() + b"\n" + moment.encode() + b"\n" + data
    signature = hmac.new(RESTORE_SIGNING_KEY, message, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        RESTORE_AGENT_URL + path, data=data if payload is not None else None, method=method,
        headers={"X-Restore-Timestamp": moment, "X-Restore-Signature": signature,
                 "Content-Type": "application/json" if payload is not None else "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.load(response)
            code = response.status
    except urllib.error.HTTPError as exc:
        try:
            result = json.load(exc)
        except Exception:
            result = {"error": "restore_agent_http_error"}
        code = exc.code
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        raise OSError("Restore-Verwaltung derzeit nicht erreichbar (" + type(exc).__name__ + ")") from exc
    if not isinstance(result, dict):
        raise OSError("Ungueltige Restore-Agent-Antwort")
    result["_http_status"] = code
    return result


def restore_confirmation_create(name):
    if not isinstance(name, str) or not BACKUP_NAME.fullmatch(name):
        raise ValueError("Ungueltige Sicherung")
    token = secrets.token_urlsafe(32)
    now = time.time()
    with RESTORE_LOCK:
        for key, item in list(RESTORE_CONFIRMATIONS.items()):
            if item[0] < now:
                RESTORE_CONFIRMATIONS.pop(key, None)
        RESTORE_CONFIRMATIONS[token] = (now + 600, name)
    return token


def restore_confirmation_take(token):
    with RESTORE_LOCK:
        record = RESTORE_CONFIRMATIONS.pop(token, None)
    if record is None or record[0] < time.time():
        raise ValueError("Restore-Bestaetigung abgelaufen oder bereits verwendet")
    return record[1]


def restore_status_table(status):
    if not isinstance(status, dict):
        status = {}
    order = ("status", "phase", "timestamp", "backup", "safety_backup", "detail")
    return "".join("<tr><th>" + html.escape(k) + "</th><td>" +
                   html.escape(str(status.get(k) or "–")) + "</td></tr>" for k in order)


def restore_is_running():
    try:
        data = restore_agent("/list", timeout=5)
        return isinstance(data.get("status"), dict) and data["status"].get("status") == "running"
    except OSError:
        return False



def auth_ok(header):
    if not header or not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
        username, password = decoded.split(":", 1)
        given = hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 260000)
        return hmac.compare_digest(username, ADMIN_USER) and hmac.compare_digest(given, HASH)
    except (ValueError, UnicodeError):
        return False


def check_sync():
    try:
        req = urllib.request.Request(SYNC_HEALTH_URL, headers={"User-Agent": "fxa-sync-manager/0.4.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            return resp.status == 200, f"HTTP {resp.status}"
    except Exception as exc:
        return False, type(exc).__name__


def probe(url, json_required=False):
    if not url:
        return False, 'Kein Endpunkt konfiguriert'
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'fxa-sync-manager/0.4.0'}), timeout=4) as r:
            data = r.read(65536)
            if json_required:
                parsed = json.loads(data)
                if not isinstance(parsed, dict) or not parsed:
                    return False, 'Ungueltige Discovery-Antwort'
            return 200 <= r.status < 400, f'HTTP {r.status}'
    except Exception as exc:
        return False, type(exc).__name__


def check_frontend_bundle():
    """Probe the same host-routed HTML and first-party main JS seen by the browser.

    Internal HTTP avoids requiring the container to resolve/trust externally terminated NPM TLS.
    Do not report login/sync success just because HTML and JS are reachable.
    """
    host = urlsplit(FXA_CONTENT).netloc
    headers = {'Host': host, 'X-Forwarded-Proto': 'https', 'User-Agent': 'fxa-sync-manager/0.4.0'}
    try:
        request = urllib.request.Request('http://fxa-proxy/', headers=headers)
        with urllib.request.urlopen(request, timeout=5) as resp:
            if resp.status != 200:
                return False, f'HTML: HTTP {resp.status}'
            page = resp.read(1024 * 1024).decode('utf-8', errors='replace')
        if 'https://cdn.accounts.firefox.com' in page:
            return False, 'HTML verweist noch auf Mozilla-CDN'
        scripts = re.findall(r'<script\b[^>]*?\bsrc=["\']([^"\']+)["\']', page, re.I)
        mains = [urlsplit(html.unescape(item)) for item in scripts if '/settings/prod/static/js/main.' in item]
        if not mains:
            return False, 'Kein Settings-Hauptbundle im HTML gefunden'
        target = mains[0]
        if target.scheme != 'https' or target.netloc != host:
            return False, 'Hauptbundle zeigt auf fremden Host/kein HTTPS'
        url = 'http://fxa-proxy' + target.path + ('?' + target.query if target.query else '')
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=5) as resp:
            mime = resp.headers.get_content_type()
            if resp.status != 200:
                return False, f'Hauptbundle: HTTP {resp.status}'
            if mime not in ('application/javascript', 'text/javascript', 'application/x-javascript'):
                return False, f'Hauptbundle: unerwarteter MIME-Typ {mime}'
            bundle = resp.read(4 * 1024 * 1024)
            if not bundle:
                return False, 'Hauptbundle ist leer'
            if b'https://cdn.accounts.firefox.com' in bundle:
                return False, 'Hauptbundle enthaelt noch Mozilla-CDN-Pfad'
        # Konkreter dynamisch geladener Chunk aus FxA v1.342.2, dessen
        # fehlgeschlagener Bezug die React-Fehlermeldung ausgelöst hat.
        # Bei anderem FXA_VERSION nur den allgemeinen HTML/Hauptbundle-Check nutzen.
        if os.environ.get('FXA_VERSION', 'v1.342.2') == 'v1.342.2':
            chunk = '/settings/prod/static/js/6901.08959258a0961575b692.chunk.js'
            chunk_url = 'http://fxa-proxy' + chunk
            try:
                with urllib.request.urlopen(urllib.request.Request(chunk_url, headers=headers), timeout=5) as resp:
                    mime = resp.headers.get_content_type()
                    if resp.status != 200 or mime not in ('application/javascript', 'text/javascript', 'application/x-javascript'):
                        return False, f'Dynamischer Chunk 6901: HTTP {resp.status}, {mime}'
                    chunk_data = resp.read(4 * 1024 * 1024)
                    if not chunk_data:
                        return False, 'Dynamischer Chunk 6901 ist leer'
                    if b'https://cdn.accounts.firefox.com' in chunk_data:
                        return False, 'Dynamischer Chunk 6901 verweist noch auf Mozilla-CDN'
            except Exception as exc:
                return False, f'Dynamischer Chunk 6901: {type(exc).__name__} (moeglicherweise 404)'
            return True, 'HTML, Hauptbundle + dynamischer Chunk 6901 lokal / HTTP 200 (kein Browser- oder Login-Test)'
        return True, 'HTML und Hauptbundle lokal / HTTP 200 (dynamische Chunks nicht geprueft)'
    except Exception as exc:
        return False, f'Frontend-Test: {type(exc).__name__}'



def _web_origin(value):
    """Canonical (scheme, hostname, port); invalid URL/origin -> None."""
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        return (parsed.scheme, parsed.hostname.lower(), parsed.port or
                (443 if parsed.scheme == "https" else 80))
    except ValueError:
        return None


def request_origin_allowed(browser_url, forwarded_host):
    """Accept configured NPM public origin OR request Host (direct LAN).

    Origin must be exactly an origin; Referer may additionally contain a path.
    Host alone may represent a local connection on an arbitrary published port;
    do not let that weaken HTTPS requirement for configured public hostname.
    """
    origin = _web_origin(browser_url)
    if origin is None:
        return False
    public = _web_origin(MANAGER_PUBLIC.strip()) if MANAGER_PUBLIC.strip() else None
    if public is not None and origin == public:
        return True
    if not forwarded_host or any(ch in forwarded_host for ch in '/?#@\\'):
        return False
    host = _web_origin('http://' + forwarded_host.strip())
    if host is None:
        return False
    # If public origin is configured, never accept an HTTP downgrade for it.
    if public is not None and host[1] == public[1]:
        return False
    # Scheme changes at TLS termination; only compare host and effective port.
    return origin[1:] == host[1:]


def account_inventory():
    """Never request password hashes, session tokens, or sync contents."""
    connection = None
    try:
        connection = pymysql.connect(
            host=RO_HOST, user=RO_USER, password=RO_PASSWORD, database="fxa",
            connect_timeout=3, read_timeout=4, write_timeout=4,
            charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
        )
        with connection.cursor() as cur:
            cur.execute("SHOW COLUMNS FROM `accounts`")
            columns = {row["Field"] for row in cur.fetchall()}
            required = {"uid", "email", "emailVerified"}
            if not required.issubset(columns):
                return None, "FxA-Schema unerwartet: UID/E-Mail/Verifikation nicht gefunden"
            created = ", `createdAt`" if "createdAt" in columns else ""
            sort = "`createdAt` DESC" if created else "`email` ASC"
            cur.execute(
                "SELECT HEX(`uid`) AS uid, `email`, `emailVerified`" + created +
                " FROM `accounts` ORDER BY " + sort + " LIMIT 200"
            )
            entries = cur.fetchall()
            cur.execute("SELECT COUNT(*) AS amount FROM `accounts`")
            total = int(cur.fetchone()["amount"])
            # Do not send raw bytes or timestamp classes as JSON.
            result = []
            for row in entries:
                c = row.get("createdAt")
                if isinstance(c, (int, float)):
                    c = datetime.fromtimestamp(c / 1000 if c > 10**11 else c, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                elif c is not None:
                    c = str(c)
                email = row["email"]
                if isinstance(email, bytes):
                    email = email.decode("utf-8", errors="replace")
                result.append({"uid": row["uid"], "email": str(email),
                               "email_verified": bool(row["emailVerified"]), "created": c})
            return {"total": total, "shown": result, "limit": 200}, None
    except Exception as exc:
        # Class name only: no credentials, SQL, connection string or email in logs.
        return None, "Lesender Datenbankzugriff fehlgeschlagen (" + type(exc).__name__ + ")"
    finally:
        if connection is not None:
            connection.close()


def user_by_uid(uid):
    """Verify exact account UID in FxA before an admin action; read-only DB user."""
    if not account_access.UID.fullmatch(uid):
        return None
    conn = None
    try:
        conn = pymysql.connect(
            host=RO_HOST, user=RO_USER, password=RO_PASSWORD, database='fxa',
            connect_timeout=3, read_timeout=4, write_timeout=4,
            charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
        )
        with conn.cursor() as cur:
            cur.execute('SELECT HEX(`uid`) AS uid, `email`, `emailVerified` '
                        'FROM `accounts` WHERE `uid` = UNHEX(%s) LIMIT 1', (uid,))
            row = cur.fetchone()
        if row is not None and isinstance(row['email'], bytes):
            row['email'] = row['email'].decode('utf-8', errors='replace')
        return row
    finally:
        if conn is not None:
            conn.close()


def format_bytes(number):
    size = float(number)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def backup_report():
    path = "/backup-status/last.json"
    try:
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
        return {k: payload.get(k) for k in ("status", "timestamp", "backup", "detail")}
    except (OSError, ValueError):
        return {"status": "pending", "detail": "Noch keine Sicherung registriert"}


def nav():
    return '<nav><a href="/">Status</a> · <a href="/users">Benutzer</a> · <a href="/registration">Registrierung</a> · <a href="/invitations">Einladungen</a> · <a href="/audit">Audit</a> · <a href="/backups">Backups</a> · <a href="/restore">Wiederherstellung</a></nav>' 


def page(title, contents):
    return ("<!doctype html><html lang='de'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Firefox Account &amp; Sync – " + html.escape(title) + "</title>"
            "<style>body{background:#0f1422;color:#edf2ff;font:16px system-ui;margin:0;line-height:1.5}"
            "main{box-sizing:border-box;width:100%;max-width:1000px;margin:3rem auto;padding:1rem}"
            "section{background:#192238;border:1px solid #36415b;border-radius:16px;padding:1.3rem;margin:1rem 0}"
            "a{color:#99ceff}table{border-collapse:collapse;width:100%;}td,th{text-align:left;"
            "padding:.5rem;border-bottom:1px solid #36415b;overflow-wrap:anywhere}"
            "code{overflow-wrap:anywhere}.warn{color:#ffcd80}.good{color:#6ee4b8}.bad{color:#ff9f9f}"
            "small{color:#b7c4e1}h1{font-size:2rem}h2{margin-top:.2rem}"
            "nav{margin:.6rem 0 1.5rem;line-height:2.0}form{margin:.6rem 0}"
            "button,input{font:inherit}button{cursor:pointer;padding:.35rem .6rem}"
            "section{overflow-x:auto}@media(max-width:650px){main{margin:1rem auto;padding:.8rem}"
            "table{display:block;overflow-x:auto;white-space:nowrap}}</style><main>"
            "<small>Firefox Account &amp; Sync · Version 0.6.0</small>" + nav() +
            "<h1>" + html.escape(title) + "</h1>" + contents + "</main></html>")



class Handler(BaseHTTPRequestHandler):
    server_version = "FirefoxAccountSyncManager/0.6.0"

    def send(self, status, body, content_type="text/html; charset=utf-8", extra=None):
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        csp = "default-src 'none'; style-src 'unsafe-inline'"
        if self.command == "GET" and urlsplit(self.path).path == "/backups" and status == 200:
            csp += "; script-src 'sha256-" + BACKUP_JS_HASH + "'"
        self.send_header("Content-Security-Policy", csp)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            return self.send(200, "ok", "text/plain; charset=utf-8")
        if self.path == "/internal/registration-allow":
            allowed, _, error = registration.policy()
            if error:
                return self.send(503, "Registration status unavailable", "text/plain; charset=utf-8")
            return self.send(204 if allowed else 403, b"", "text/plain; charset=utf-8")
        if urlsplit(self.path).path not in ("/", "/api/status", "/users", "/api/users", "/backups", "/api/backups", "/restore", "/api/restore", "/registration", "/audit", "/api/registration", "/invitations", "/api/invitations", "/users/detail"):

            return self.send(404, "Not found", "text/plain; charset=utf-8")
        if not auth_ok(self.headers.get("Authorization")):
            return self.send(401, "Anmeldung erforderlich", "text/plain; charset=utf-8", {
                "WWW-Authenticate": 'Basic realm="Firefox Account Sync - Manager", charset="UTF-8"'
            })
        if self.path in ("/registration", "/api/registration"):
            current, when, error = registration.mode()
            if self.path == "/api/registration":
                return self.send(200 if not error else 503,
                                 json.dumps({"mode": current, "enabled": current == "open", "updated_at": when, "error": error}),
                                 "application/json; charset=utf-8")
            buttons = ""
            for value, label in (("open", "OFFEN – jeder darf sich registrieren"),
                                 ("closed", "GESPERRT – keine neuen Konten"),
                                 ("invite", "NUR FREIGEGEBENE E-MAILS")):
                disabled = " disabled" if current == value else ""
                buttons += ("<form method='post' action='/registration/action'>"
                            "<input type='hidden' name='csrf' value='" + html.escape(CSRF, quote=True) + "'>"
                            "<input type='hidden' name='action' value='" + value + "'>"
                            "<button type='submit'" + disabled + ">" + label + "</button></form>")
            note = "<p class='warn'>" + html.escape(error) + "</p>" if error else ""
            body = ("<section><h2>Registrierung: " + html.escape(current.upper()) + "</h2>"
                    "<p>Stand: " + html.escape(when) + "</p>" + note + buttons + "</section>"
                    "<section><p>Im Modus NUR FREIGEGEBENE E-MAILS werden Kontoerstellungen nur fuer "
                    "hinterlegte, noch gueltige E-Mail-Adressen akzeptiert. "
                    "Bestehende Konten, Login, OAuth und Sync bleiben unabhaengig davon erreichbar.</p>"
                    "<p><a href='/invitations'>E-Mail-Freigaben verwalten</a></p>"
                    "<p class='warn'>Technisch wird bei der Kontoerstellung /v1/account/create gefiltert; "
                    "der FxA-Endpunkt /v1/account/stub wird nur bei OFFEN zugelassen. "
                    "Weitere Kontoerstellungswege zukuenftiger FxA-Versionen muessen vor einem Update geprueft werden.</p></section>")
            return self.send(200 if not error else 503, page("Registrierung", body))
        if self.path in ("/invitations", "/api/invitations"):
            try:
                entries = registration.invitations()
            except OSError:
                return self.send(503, page("Einladungen", "<section>Einladungsliste nicht lesbar. Vorsorglich keine Freigabe.</section>"))
            if self.path == "/api/invitations":
                return self.send(200, json.dumps({"emails": entries}), "application/json; charset=utf-8")
            rows = ""
            for entry in entries:
                email = html.escape(entry["email"])
                rows += ("<tr><td>" + email + "</td><td>" + html.escape(entry["expires_at"]) +
                         "</td><td>" + ("aktiv" if entry["active"] else "abgelaufen") + "</td><td>"
                         "<form method='post' action='/invitations/action'>"
                         "<input type='hidden' name='csrf' value='" + html.escape(CSRF, quote=True) + "'>"
                         "<input type='hidden' name='action' value='revoke'>"
                         "<input type='hidden' name='email' value='" + html.escape(entry["email"], quote=True) + "'>"
                         "<button>Freigabe entfernen</button></form></td></tr>")
            body = ("<section><h2>E-Mail-Adresse zur Registrierung freigeben</h2>"
                    "<form method='post' action='/invitations/action'>"
                    "<input type='hidden' name='csrf' value='" + html.escape(CSRF, quote=True) + "'>"
                    "<input type='hidden' name='action' value='add'>"
                    "<label>E-Mail <input name='email' type='email' required maxlength='254'></label> "
                    "<label>Tage (1–90) <input name='days' type='number' min='1' max='90' value='7'></label> "
                    "<button>Freigeben</button></form></section>"
                    "<section><h2>Freigaben (" + str(len(entries)) + ")</h2>"
                    "<table><tr><th>E-Mail</th><th>Gueltig bis UTC</th><th>Status</th><th>Aktion</th></tr>" + rows + "</table></section>"
                    "<section><p>Freigabe ist an die genaue E-Mail-Adresse gebunden, kein Einmal-Link. "
                    "Der Benutzer registriert sich weiterhin selbst auf der Mozilla-Account-Seite "
                    "und bestaetigt seine Mail wie gewohnt ueber Mailpit.</p>"
                    "<p class='warn'>Mailpit verschickt NICHT automatisch Einladungs-E-Mails. "
                    "Freigaben sind ausschliesslich bei aktivem Modus NUR FREIGEGEBENE E-MAILS wirksam.</p></section>")
            return self.send(200, page("Einladungen", body))
        if self.path == "/audit":
            events = registration.audit_entries()
            rows = "".join("<tr><td>" + html.escape(str(item.get("at", "–"))) + "</td><td>" +
                           html.escape(str(item.get("actor", "–"))) + "</td><td>" +
                           html.escape(str(item.get("action", "–"))) + "</td><td><code>" +
                           html.escape(str(item.get("uid", "–"))) + "</code></td></tr>" for item in events)
            body = "<section><p>Lokale Manager-Aktionen (max. 80 letzte Zeilen, keine Kontopasswoerter).</p>"+                    "<table><thead><tr><th>Zeit UTC</th><th>Admin</th><th>Aktion</th><th>UID</th></tr></thead><tbody>" + rows + "</tbody></table></section>"
            return self.send(200, page("Auditprotokoll", body))
        path = urlsplit(self.path).path
        if path == "/users/detail":
            query = parse_qs(urlsplit(self.path).query)
            uid = query.get('uid', [''])[0]
            if not account_access.UID.fullmatch(uid):
                return self.send(400, page('Benutzer', '<section>Ungueltige Benutzer-ID.</section>'))
            try:
                row = user_by_uid(uid)
                blocks = account_access.read_blocks()
            except (pymysql.MySQLError, OSError, ValueError):
                return self.send(503, page('Benutzer', '<section>Benutzerstatus nicht abrufbar. Keine Aenderung moeglich.</section>'))
            if row is None:
                return self.send(404, page('Benutzer', '<section>Benutzer nicht gefunden.</section>'))
            is_blocked = uid in blocks
            action = 'unblock_login' if is_blocked else 'block_login'
            button = 'Neue Anmeldung wieder erlauben' if is_blocked else 'Neue Anmeldung sperren'
            status = 'NEUANMELDUNG GESPERRT' if is_blocked else 'Neuanmeldung erlaubt'
            email = html.escape(str(row['email']))
            body = ("<section><h2>" + email + "</h2><p>UID: <code>" + uid + "</code></p>"
                    "<p>E-Mail bestaetigt: " + ('Ja' if row['emailVerified'] else 'Nein') + "</p>"
                    "<p>Status: <strong>" + status + "</strong></p>"
                    "<p class='warn'>Diese Aktion sperrt NUR neue Anmeldungen am Endpunkt "
                    "<code>/v1/account/login</code>. Bereits angemeldete Firefox-Profile, "
                    "bestehende Sitzungen, OAuth-Refresh-Tokens und Sync bleiben aktiv. "
                    "Dies ist KEINE vollstaendige Kontosperre.</p></section>"
                    "<section><h2>Aktion bestaetigen</h2>"
                    "<form method='post' action='/users/action'>"
                    "<input type='hidden' name='csrf' value='" + html.escape(CSRF, quote=True) + "'>"
                    "<input type='hidden' name='uid' value='" + uid + "'>"
                    "<input type='hidden' name='action' value='" + action + "'>"
                    "<label>E-Mail zur Bestaetigung exakt eingeben "
                    "<input type='text' name='confirm_email' maxlength='254' required autocomplete='off'></label> "
                    "<button type='submit'>" + button + "</button></form></section>"
                    "<p><a href='/users'>Zur Benutzerliste</a></p>")
            return self.send(200, page('Benutzerdetails', body))
        if self.path in ("/users", "/api/users"):
            users, error = account_inventory()
            try:
                blocks = account_access.read_blocks()
            except (OSError, ValueError):
                blocks = None
                error = 'Neuanmeldungsstatus nicht lesbar; Benutzerliste vorsorglich deaktiviert'
            if users is not None and blocks is not None:
                for user in users['shown']:
                    user['new_login_blocked'] = user['uid'] in blocks
            if self.path == "/api/users":
                code = 200 if users is not None else 503
                return self.send(code, json.dumps({"accounts": users, "error": error}),
                                 "application/json; charset=utf-8")
            if error:
                body = "<section><p class='warn'>" + html.escape(error) + "</p>" + (
                    "<p>Bitte einmalige Datenbank-Freigabe pruefen: "
                    "<code>docker compose logs fxa-manager-readonly-grants</code>.</p></section>")
            else:
                rows = "".join(
                    "<tr><td><a href='/users/detail?uid=" + html.escape(a['uid'], quote=True) + "'>" +
                    html.escape(a['email']) + "</a></td><td>" +
                    ("Ja" if a['email_verified'] else "Nein") + "</td><td><code>" +
                    html.escape(a['uid']) + "</code></td><td>" +
                    html.escape(a['created'] or "–") + "</td><td>" +
                    ("Neue Anmeldung gesperrt" if a['new_login_blocked'] else "Neue Anmeldung erlaubt") +
                    "</td></tr>" for a in users['shown']
                )
                body = ("<section><p>Konten insgesamt: " + str(users["total"]) +
                        "; Anzeige der ersten " + str(len(users["shown"])) +
                        " (maximal 200).</p><table><thead><tr><th>E-Mail</th>"
                        "<th>Bestaetigt</th><th>UID</th><th>Erstellt</th><th>Neuanmeldungen</th></tr></thead>"
                        "<tbody>" + rows + "</tbody></table></section>")
            body += ("<section><p class='warn'>Neue Anmeldungen koennen pro Konto unter Benutzerdetails "
                     "gesperrt oder wieder erlaubt werden. Vorhandene Sitzungen und Sync bleiben bestehen. "
                     "Keine vollstaendige Kontosperre; Geräte/Sitzungen können hier noch nicht widerrufen werden.</p>"
                     "<p>Die eigene Kontoeinstellung liegt unter "
                     "<a href='" + html.escape(FXA_CONTENT, quote=True) +
                     "/settings'>Mozilla Accounts</a>.</p></section>")
            return self.send(200 if not error else 503, page("Benutzer", body))
        if self.path in ("/restore", "/api/restore"):
            try:
                data = restore_agent("/list")
                backups = data.get("backups", [])
                status = data.get("status", {})
                restore_error = None
                if not isinstance(backups, list) or any(not isinstance(x, dict) for x in backups):
                    raise OSError("Ungueltige Restore-Liste")
            except OSError as exc:
                backups, status = [], {"status": "unavailable", "detail": str(exc)}
                restore_error = str(exc)
            if self.path == "/api/restore":
                return self.send(503 if restore_error else 200, json.dumps({"status": status, "backups": backups, "error": restore_error}),
                                 "application/json; charset=utf-8")
            body = ("<section><h2>Wiederherstellungsstatus</h2><table>" + restore_status_table(status) + "</table>"
                    "<p><a href='/restore'>Status aktualisieren</a></p></section>")
            if restore_error:
                body += "<section><p class='bad'>" + html.escape(restore_error) + "</p></section>"
            else:
                rows = "".join(
                    "<tr><td><code>" + html.escape(item.get("name", "")) + "</code></td><td>" +
                    html.escape(item.get("date_utc", "–")) + "</td><td>" +
                    html.escape(format_bytes(item.get("size_bytes", 0))) + "</td><td>" +
                    "<form method='post' action='/restore/action'>"
                    "<input type='hidden' name='csrf' value='" + html.escape(CSRF, quote=True) + "'>"
                    "<input type='hidden' name='action' value='inspect'>"
                    "<input type='hidden' name='backup' value='" + html.escape(item.get("name", ""), quote=True) + "'>"
                    "<button type='submit'>Prüfen …</button></form></td></tr>" for item in backups
                    if isinstance(item.get("name"), str) and BACKUP_NAME.fullmatch(item.get("name", "")))
                if not rows:
                    rows = "<tr><td colspan='4'>Keine abgeschlossenen Backups vorhanden.</td></tr>"
                body += ("<section><h2>Backup auswählen</h2><table><thead><tr><th>Sicherung</th><th>Zeit UTC</th><th>Größe</th><th>Aktion</th></tr></thead>"
                         "<tbody>" + rows + "</tbody></table></section>")
            body += ("<section><h2>Offline-Restore</h2>"
                     "<p>Vor dem eigentlichen Restore müssen in UGOS die schreibenden FxA/Sync-Dienste gestoppt sein. "
                     "Die Prüfung nennt konkret, welche Container noch antworten. Datenbank-Container, Redis, Manager und restore-admin bleiben aktiv.</p>"
                     "<p>Vor jeder Wiederherstellung wird automatisch ein neues Sicherheitsbackup des aktuellen Zustands erzeugt. "
                     "Schlägt der Restore fehl, versucht der Restore-Dienst automatisch auf dieses Sicherheitsbackup zurückzugehen.</p>"
                     "<p class='warn'>Die aktuelle <code>.env</code> wird nicht automatisch überschrieben. Identitätskritische Werte müssen zum Backup passen. "
                     "Nach erfolgreichem Restore die zuvor gestoppten Dienste in UGOS wieder starten.</p></section>")
            return self.send(200 if not restore_error else 503, page("Wiederherstellung", body))
        if self.path in ("/backups", "/api/backups"):
            report = backup_report()
            try:
                backups = backup_inventory()
                inventory_error = None
            except (OSError, KeyError, TypeError):
                backups = []
                inventory_error = "Sicherungsliste nicht verfuegbar; Loeschen deaktiviert. Backup-Admin pruefen."
            last_name = report.get("backup")
            if not inventory_error and last_name and last_name not in {entry["name"] for entry in backups}:
                report["detail"] = "Zuletzt registrierte Sicherung wurde inzwischen geloescht; neue Sicherung wird regulaer erstellt."
                report["status"] = "deleted"
            if self.path == "/api/backups":
                return self.send(503 if inventory_error else 200, json.dumps({
                    "last": report, "backups": backups, "error": inventory_error
                }), "application/json; charset=utf-8")
            fields = "".join("<tr><th>" + html.escape(k) + "</th><td>" +
                             html.escape(str(v if v is not None else "–")) + "</td></tr>" for k, v in report.items())
            body = "<section><h2>Letzter Sicherungsstatus</h2><table>" + fields + "</table></section>"
            if inventory_error:
                body += "<section><p class='bad'>" + inventory_error + "</p></section>"
            else:
                rows = "".join(
                    "<tr><td><label><input type='checkbox' name='backup' value='" +
                    html.escape(item["name"], quote=True) + "'> auswählen</label></td><td><code>" +
                    html.escape(item["name"]) + "</code></td><td>" +
                    html.escape(item["date_utc"]) + "</td><td>" +
                    html.escape(format_bytes(item["size_bytes"])) + "</td></tr>"
                    for item in backups
                )
                if not backups:
                    rows = "<tr><td colspan='4'>Keine abgeschlossenen Backups vorhanden.</td></tr>"
                body += ("<section><h2>Vorhandene Backups (" + str(len(backups)) + ")</h2>"
                         "<p>Nur abgeschlossene Sicherungsordner; laufende Sicherungen werden nicht angeboten.</p>"
                         "<form method='post' action='/backups/delete'>"
                         "<input type='hidden' name='csrf' value='" + html.escape(CSRF, quote=True) + "'>"
                         "<table><thead><tr><th><label><input type='checkbox' id='toggle-backups'> Alle auswählen</label>"
                         "</th><th>Sicherung</th><th>Zeit UTC</th><th>Größe</th></tr></thead>"
                         "<tbody>" + rows + "</tbody></table>"
                         "<p><button type='submit' name='action' value='preview_selected'" +
                         (" disabled" if not backups else "") + ">Markierte löschen …</button> "
                         "<button type='submit' name='action' value='preview_all'" +
                         (" disabled" if not backups else "") + ">ALLE Backups löschen …</button></p>"
                         "</form><script>" + BACKUP_JS + "</script></section>")
            body += ("<section><p>Automatische DB-Dumps, Schluessel, generierte Konfiguration, "
                     "Profilbilder und .env.</p><p><a href='/restore'>Backup prüfen oder wiederherstellen</a>.</p>"
                     "<p>Manuelle Sicherung: <code>docker compose exec backup "
                     "/bin/sh /opt/backup/run.sh once</code></p>"
                     "<p class='warn'>Löschen ist dauerhaft und entfernt ganze Sicherungsordner "
                     "einschließlich .env und Schlüssel-Snapshot. Aktuelle Datenbanken, "
                     "laufende Sicherungen und Docker-Volumes bleiben unverändert. "
                     "Wiederherstellung ist unter <a href='/restore'>Wiederherstellung</a> verfügbar; produktiven Restore zuerst mit einem entbehrlichen Teststand prüfen.</p></section>")
            return self.send(200 if not inventory_error else 503, page("Backups", body))
        healthy, reason = check_sync()
        discovery, discovery_reason = probe(FXA_DISCOVERY_HEALTH_URL, json_required=True)
        auth, auth_reason = probe(FXA_AUTH_HEALTH_URL)
        frontend, frontend_reason = check_frontend_bundle()
        if self.path == "/api/status":
            return self.send(200, json.dumps({
                "sync_heartbeat": healthy,
                "sync_heartbeat_detail": reason,
                "account_server_discovery": discovery,
                "account_server_discovery_detail": discovery_reason,
                "account_server_auth_http": auth,
                "account_server_auth_detail": auth_reason,
                "frontend_js_reachable": frontend,
                "frontend_js_detail": frontend_reason,
                "firefox_end_to_end_sync": "NOT_AUTOMATICALLY_TESTED",
                "sync_public_url": PUBLIC_SYNC,
            }), "application/json; charset=utf-8")
        label = "ERREICHBAR" if healthy else "NICHT ERREICHBAR"
        klass = "good" if healthy else "bad"
        body = f"""<section><h2>Syncstorage + Tokenserver</h2><strong class="{klass}">{label}</strong><p>Healthcheck: {html.escape(reason)}</p>
<p>Für Firefox konfigurierter Storage-Endpunkt: <code>{html.escape(PUBLIC_SYNC)}</code></p></section>
<section><h2>Eigene Mozilla Accounts (FxA) – experimentell</h2>
<p>Discovery: <strong class="{'good' if discovery else 'bad'}">{'ERREICHBAR' if discovery else 'NICHT ERREICHBAR'}</strong> ({html.escape(discovery_reason)})</p>
<p>Auth HTTP: <strong class="{'good' if auth else 'bad'}">{'ANTWORTET' if auth else 'KEINE ANTWORT'}</strong> ({html.escape(auth_reason)})</p>
<p>Account-Frontend (HTML + JS): <strong class="{'good' if frontend else 'bad'}">{'ERREICHBAR' if frontend else 'FEHLER'}</strong> ({html.escape(frontend_reason)})</p>
<p>Login-Adresse: <code>{html.escape(FXA_CONTENT)}</code></p><p>OAuth-Adresse: <code>{html.escape(FXA_OAUTH)}</code></p>
<p class="warn">Der Status prueft keine echte Browser-Sitzung. Registrierung und Sync mit zwei Firefox-Profilen wurden bei dieser Installation manuell bestaetigt.</p></section>
<section><h2>Zugriff</h2><p>Lokal/LAN: <code>http://SERVER-IP:{html.escape(os.environ.get('MANAGER_HTTP_PORT_DISPLAY','18081'))}</code></p>
<p>NPM-Adresse: <code>{html.escape(MANAGER_PUBLIC)}</code></p>
<p>Neuanmeldungen können pro Konto gesperrt werden. Bereits bestehende Geräte, Sitzungen und Sync-Tokens werden noch nicht widerrufen.</p></section>
<p><a href="/">Status aktualisieren</a></p><small>Admin-Zugangsdaten nur über HTTPS oder vertrauenswürdiges LAN/VPN eingeben.</small>"""
        body = page("Serverstatus", body)
        return self.send(200, body)

    def do_POST(self):
        if self.path not in ("/registration/action", "/invitations/action", "/users/action", "/backups/delete", "/restore/action"):
            return self.send(404, "Not found", "text/plain; charset=utf-8")
        if not auth_ok(self.headers.get("Authorization")):
            return self.send(401, "Anmeldung erforderlich", "text/plain; charset=utf-8", {
                "WWW-Authenticate": 'Basic realm="Firefox Account Sync - Manager", charset="UTF-8"'
            })
        if self.path != "/restore/action" and restore_is_running():
            return self.send(409, page("Wiederherstellung aktiv",
                "<section class='warn'>Während einer Wiederherstellung sind andere Manager-Änderungen gesperrt. "
                "<a href='/restore'>Restore-Status öffnen</a>.</section>"))
        # UGOS/NPM can rewrite Host and X-Forwarded-* independently of the
        # browser Origin; this app also sends Referrer-Policy: no-referrer.
        # Therefore do NOT use either proxy-dependent header as the CSRF gate.
        # The 256-bit random per-process CSRF token, authenticated GET of its
        # form, no CORS, frame denial, and Basic Auth provide the CSRF boundary.
        # The token check below MUST be retained for all state-changing POSTs.
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
            return self.send(415, "Ungueltiger Content-Type", "text/plain; charset=utf-8")
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        max_size = 131072 if self.path == "/backups/delete" else 4096
        if length < 1 or length > max_size:
            return self.send(413, "Ungueltige Formulargroesse", "text/plain; charset=utf-8")
        try:
            form = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True, max_num_fields=2200 if self.path == "/backups/delete" else 12)
        except (UnicodeError, ValueError):
            return self.send(400, "Ungueltiges Formular", "text/plain; charset=utf-8")
        if not hmac.compare_digest(form.get("csrf", [""])[0], CSRF):
            return self.send(403, "Ungueltiger CSRF-Token", "text/plain; charset=utf-8")
        action = form.get("action", [""])[0]
        if self.path == "/restore/action":
            if action == "inspect":
                name = form.get("backup", [""])[0]
                if not BACKUP_NAME.fullmatch(name):
                    return self.send(400, page("Wiederherstellung", "<section>Ungueltige Sicherung.</section>"))
                try:
                    info = restore_agent("/inspect", {"backup": name})
                except OSError:
                    return self.send(503, page("Wiederherstellung", "<section class='bad'>Restore-Pruefung nicht erreichbar.</section>"))
                mismatches = info.get("env_mismatches", []) if isinstance(info.get("env_mismatches", []), list) else []
                writers = info.get("active_writers", []) if isinstance(info.get("active_writers", []), list) else []
                checks = ("<table><tr><th>SHA256</th><td>" + ("OK" if info.get("checksums_ok") else "FEHLER") + "</td></tr>"
                          "<tr><th>SQL-GZIP</th><td>" + ("OK" if info.get("sql_gzip_ok") else "FEHLER") + "</td></tr>"
                          "<tr><th>FxA-Volumes-Archiv</th><td>" + ("OK" if info.get("archive_ok") else "FEHLER") + "</td></tr>"
                          "<tr><th>.env kompatibel</th><td>" + ("JA" if info.get("env_compatible") else "NEIN") + "</td></tr></table>")
                details = "<p>" + html.escape(str(info.get("detail", "–"))) + "</p>"
                if mismatches:
                    details += "<p class='bad'>Abweichende/fehlende .env-Werte: <code>" + html.escape(", ".join(map(str, mismatches))) + "</code></p>"
                if writers:
                    details += ("<p class='warn'>Diese Container antworten noch und müssen vor dem Restore in UGOS gestoppt werden: <code>" +
                                html.escape(", ".join(map(str, writers))) + "</code></p>")
                if info.get("pending_backup"):
                    details += "<p class='warn'>Eine Sicherung läuft noch. Warten, bis der .pending-Ordner verschwunden ist.</p>"
                body = "<section><h2><code>" + html.escape(name) + "</code></h2>" + checks + details + "</section>"
                if info.get("can_restore"):
                    token = restore_confirmation_create(name)
                    body += ("<section><h2>Restore bestätigen</h2>"
                             "<p class='bad'>Datenbanken, FxA-Schlüssel, generierte Konfiguration, Profilbilder und Managerstatus werden auf den Stand dieses Backups zurückgesetzt.</p>"
                             "<form method='post' action='/restore/action'>"
                             "<input type='hidden' name='csrf' value='" + html.escape(CSRF, quote=True) + "'>"
                             "<input type='hidden' name='token' value='" + html.escape(token, quote=True) + "'>"
                             "<label>Zur Bestätigung Backup-Namen exakt eingeben: <input name='confirm_name' required autocomplete='off'></label><br>"
                             "<label><input type='checkbox' name='overwrite' value='yes' required> Aktuellen Zustand überschreiben</label><br>"
                             "<button type='submit' name='action' value='confirm'>Wiederherstellung starten</button> "
                             "<button type='submit' name='action' value='cancel'>Abbrechen</button></form></section>")
                else:
                    body += "<section><p>Restore ist noch nicht freigegeben. Ursache oben beheben und anschließend erneut <strong>Prüfen</strong>.</p></section>"
                return self.send(200, page("Wiederherstellung prüfen", body))
            if action == "cancel":
                with RESTORE_LOCK:
                    RESTORE_CONFIRMATIONS.pop(form.get("token", [""])[0], None)
                return self.send(303, b"", extra={"Location": "/restore"})
            if action != "confirm":
                return self.send(400, "Ungueltige Restore-Aktion", "text/plain; charset=utf-8")
            try:
                name = restore_confirmation_take(form.get("token", [""])[0])
                if form.get("confirm_name", [""])[0] != name or form.get("overwrite", [""])[0] != "yes":
                    return self.send(400, page("Wiederherstellung", "<section>Bestätigung stimmt nicht überein.</section>"))
                outcome = restore_agent("/restore", {"backup": name})
                if not outcome.get("accepted"):
                    detail = outcome.get("inspect", {}).get("detail", "Restore wurde vom Restore-Dienst abgelehnt")
                    return self.send(409, page("Wiederherstellung", "<section class='warn'>" + html.escape(str(detail)) + "</section>"))
                try:
                    registration._audit(ADMIN_USER, "restore_started:" + name)
                except OSError:
                    print("WARN: Restore gestartet, Audit konnte nicht geschrieben werden", flush=True)
                return self.send(303, b"", extra={"Location": "/restore"})
            except (OSError, ValueError, KeyError, TypeError):
                return self.send(503, page("Wiederherstellung", "<section class='bad'>Restore konnte nicht gestartet werden. Bitte erneut prüfen.</section>"))
        if self.path == "/backups/delete":
            if action in ("preview_selected", "preview_all"):
                try:
                    inventory = backup_inventory()
                    available = {entry["name"] for entry in inventory}
                    selected = form.get("backup", [])
                    if action == "preview_all":
                        selected = [entry["name"] for entry in inventory]
                    if not selected or len(selected) != len(set(selected)) or any(
                            not BACKUP_NAME.fullmatch(n) or n not in available for n in selected):
                        return self.send(400, page("Backups", "<section>Keine gueltigen Sicherungen ausgewaehlt. "
                                                        "<a href='/backups'>Zurueck</a></section>"))
                    confirm_token = backup_confirmation_create(selected)
                except (OSError, ValueError, KeyError, TypeError):
                    return self.send(503, page("Backups", "<section>Auswahl konnte nicht sicher geprueft werden. "
                                                    "<a href='/backups'>Zurueck</a></section>"))
                names = "".join("<li><code>" + html.escape(n) + "</code></li>" for n in selected)
                body = ("<section><h2>" + str(len(selected)) + " Sicherung(en) dauerhaft loeschen?</h2>"
                        "<p class='bad'>Die ausgewählten Ordner inklusive Datenbankdumps, "
                        ".env und FxA-Schlüssel werden unwiederbringlich entfernt.</p>"
                        "<ul>" + names + "</ul>"
                        "<form method='post' action='/backups/delete'>"
                        "<input type='hidden' name='csrf' value='" + html.escape(CSRF, quote=True) + "'>"
                        "<input type='hidden' name='token' value='" + html.escape(confirm_token, quote=True) + "'>"
                        "<button name='action' value='confirm' type='submit'>Endgültig löschen</button> "
                        "<button name='action' value='cancel' type='submit'>Abbrechen</button>"
                        "</form></section>")
                return self.send(200, page("Löschen bestätigen", body))
            if action == "cancel":
                with BACKUP_LOCK:
                    BACKUP_CONFIRMATIONS.pop(form.get("token", [""])[0], None)
                return self.send(303, b"", extra={"Location": "/backups"})
            if action != "confirm":
                return self.send(400, "Ungueltige Backup-Aktion", "text/plain; charset=utf-8")
            try:
                selected = backup_confirmation_take(form.get("token", [""])[0])
                outcome = backup_agent("/delete", {"backups": selected})
                deleted = outcome["deleted"]
                if deleted != selected:
                    raise OSError("Backup-Loeschung wurde nur teilweise ausgefuehrt")
                for name in deleted:
                    try:
                        registration._audit(ADMIN_USER, "backup_deleted:" + name)
                    except OSError:
                        print("WARN: Backup geloescht, Audit konnte nicht geschrieben werden", flush=True)
                return self.send(303, b"", extra={"Location": "/backups"})
            except (OSError, ValueError, KeyError, TypeError):
                return self.send(503, page("Backups", "<section class='bad'>"
                    "Backup-Loeschung fehlgeschlagen oder nicht vollstaendig. "
                    "Bitte Backup-Liste aktualisieren und den Backup-Admin-Log pruefen. "
                    "<a href='/backups'>Zurueck zu Backups</a></section>"))
        if self.path == "/users/action":
            uid = form.get('uid', [''])[0]
            confirm_email = form.get('confirm_email', [''])[0]
            if action not in ('block_login', 'unblock_login') or not account_access.UID.fullmatch(uid):
                return self.send(400, 'Ungueltige Benutzeraktion', 'text/plain; charset=utf-8')
            try:
                account = user_by_uid(uid)
                if account is None:
                    return self.send(404, 'Benutzer nicht gefunden', 'text/plain; charset=utf-8')
                if str(account['email']) != confirm_email:
                    return self.send(400, page('Fehler', '<section>E-Mail-Bestaetigung stimmt nicht mit dem Konto ueberein.</section>'))
                account_access.change_login(uid, action == 'block_login', ADMIN_USER)
            except (OSError, ValueError, pymysql.MySQLError):
                return self.send(503, page('Fehler', '<section>Kontostatus nicht sicher aktualisierbar; keine Aenderung vorgenommen bzw. Auditstatus pruefen.</section>'))
            return self.send(303, b'', extra={'Location': '/users/detail?uid=' + uid})
        if self.path == "/registration/action":
            if action not in ("open", "close", "closed", "invite"):
                return self.send(400, "Ungueltige Aktion", "text/plain; charset=utf-8")
            try:
                registration.change_mode("closed" if action in ("close", "closed") else action, ADMIN_USER)
            except OSError:
                return self.send(503, page("Fehler", "<section>Managerstatus/Audit nicht schreibbar; Volume pruefen.</section>"))
            return self.send(303, b"", extra={"Location": "/registration"})
        if action not in ("add", "revoke"):
            return self.send(400, "Ungueltige Aktion", "text/plain; charset=utf-8")
        try:
            email = form.get("email", [""])[0]
            if action == "add":
                registration.invite(email, int(form.get("days", ["7"])[0]), ADMIN_USER)
            else:
                registration.revoke(email, ADMIN_USER)
        except (ValueError, OSError):
            return self.send(400, page("Fehler", "<section>E-Mail, Gueltigkeit oder Einladungsliste ungueltig / nicht schreibbar.</section>"))
        return self.send(303, b"", extra={"Location": "/invitations"})

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} {time.strftime('%Y-%m-%dT%H:%M:%S%z')} {args[1] if len(args)>1 else '-'}", flush=True)


if __name__ == "__main__":
    print("Firefox Account & Sync Manager v0.6.0 gestartet – Authentifizierung aus .env/Umgebungsvariablen (keine Secret-Datei)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
