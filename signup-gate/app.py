"""Proxy for FxA v1.342.2 signup and NEW account/login, no published port.

Login block is keyed by the real FxA account UID, resolved by a SELECT-only
DB user. It does NOT revoke existing login sessions or active Sync tokens.
"""
import datetime as dt
import hashlib
import http.client
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pymysql

HTTPConnection = http.client.HTTPConnection
DIR = os.environ.get('MANAGER_STATE_DIR', '/manager-state')
CONTENT_URL = os.environ['FXA_CONTENT_URL'].rstrip('/')
HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
       'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-length', 'accept-encoding'}
# Exactly the existing ADMIN_PASSWORD, as in manager and readonly DB grant job.
# Do not accept an obsolete second password seed.
RO_PASSWORD = hashlib.sha256(
    b'fxa-manager-ro-v1\x00' + os.environ['ADMIN_PASSWORD'].encode('utf-8')
).hexdigest()


def mode():
    path = os.path.join(DIR, 'registration.json')
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        return 'open'
    if not isinstance(data, dict):
        raise ValueError('invalid registration state')
    if data.get('version') == 2 and data.get('mode') in ('open', 'closed', 'invite'):
        return data['mode']
    if type(data.get('enabled')) is bool:
        return 'open' if data['enabled'] else 'closed'
    raise ValueError('invalid registration state')


def invite_ok(email):
    try:
        with open(os.path.join(DIR, 'invitations.json'), encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        return False
    if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('emails'), dict):
        raise ValueError('invalid invite file')
    entry = data['emails'].get(email.strip().lower())
    if not isinstance(entry, dict):
        return False
    expiry = dt.datetime.fromisoformat(entry['expires_at'])
    return expiry.tzinfo is not None and expiry > dt.datetime.now(dt.timezone.utc)


def login_blocks():
    try:
        with open(os.path.join(DIR, 'login-blocks.json'), encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('blocked_uids'), dict):
        raise ValueError('invalid block file')
    blocks = data['blocked_uids']
    if len(blocks) > 20000:
        raise ValueError('invalid block count')
    for uid, entry in blocks.items():
        if not re.fullmatch('[0-9A-F]{32}', uid) or not isinstance(entry, dict) or not isinstance(entry.get('at'), str):
            raise ValueError('invalid block entry')
    return blocks


def blocked_for_email(email):
    """Resolve email on each login, so changed email does not bypass UID block."""
    blocks = login_blocks()
    if not blocks:
        return False
    connection = pymysql.connect(host='fxa-db', user='fxa_manager_ro',
        password=RO_PASSWORD, database='fxa', connect_timeout=3,
        read_timeout=4, write_timeout=4, charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor, autocommit=True)
    try:
        with connection.cursor() as cur:
            cur.execute('SELECT HEX(`uid`) AS uid FROM `accounts` WHERE LOWER(`email`) = LOWER(%s) LIMIT 1', (email,))
            row = cur.fetchone()
        return bool(row and row['uid'] in blocks)
    finally:
        connection.close()


class Handler(BaseHTTPRequestHandler):
    server_version = 'FxASignupGate/0.5.6'

    def _reply(self, code, data, content_type='application/json; charset=utf-8', extra=()):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if self.headers.get('Origin') == CONTENT_URL:
            self.send_header('Access-Control-Allow-Origin', CONTENT_URL)
            self.send_header('Access-Control-Allow-Credentials', 'true')
            self.send_header('Vary', 'Origin')
        for k, v in extra:
            if k.lower() not in HOP and k.lower() not in ('content-length', 'content-type', 'access-control-allow-origin', 'access-control-allow-credentials'):
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _deny(self, status, detail):
        self._reply(status, json.dumps({'code': status, 'error': 'Forbidden' if status == 403 else 'Service Unavailable',
                                        'message': detail}).encode('utf-8'))

    def _forward(self, data):
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP and k.lower() != 'host'}
        headers['Host'] = self.headers.get('Host', 'api')
        headers['Accept-Encoding'] = 'identity'
        conn = HTTPConnection('fxa-auth-server', 9000, timeout=15)
        try:
            conn.request(self.command, self.path, body=data, headers=headers)
            response = conn.getresponse()
            payload = response.read(2 * 1024 * 1024 + 1)
            if len(payload) > 2 * 1024 * 1024:
                return self._deny(503, 'Auth-Server response too large')
            response_headers = response.getheaders()
            mime = response.getheader('Content-Type', 'application/json; charset=utf-8')
            self._reply(response.status, payload, mime, response_headers)
        except (OSError, TimeoutError, http.client.HTTPException):
            self._deny(503, 'Auth-Server not available')
        finally:
            conn.close()

    def do_GET(self):
        if self.path == '/healthz':
            return self._reply(200, b'{"status":"ok"}')
        return self._deny(403, 'Only account/create and account/login requests accepted')

    def do_OPTIONS(self):
        if urlsplit(self.path).path not in ('/v1/account/create', '/v1/account/login'):
            return self._deny(403, 'Unsupported endpoint')
        self._forward(None)

    def do_POST(self):
        endpoint = urlsplit(self.path).path
        if endpoint not in ('/v1/account/create', '/v1/account/login'):
            return self._deny(403, 'Unsupported endpoint')
        if self.headers.get('Transfer-Encoding'):
            return self._deny(403, 'Chunked request body not supported')
        if self.headers.get('Content-Type', '').split(';', 1)[0].strip().lower() != 'application/json':
            return self._deny(403, 'JSON required')
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            length = -1
        if length < 1 or length > 65536:
            return self._deny(403, 'Invalid request size')
        data = self.rfile.read(length)
        if len(data) != length:
            return self._deny(403, 'Incomplete request')
        try:
            payload = json.loads(data)
            email = payload.get('email') if isinstance(payload, dict) else None
            if endpoint == '/v1/account/create':
                current = mode()
                if current == 'closed':
                    return self._deny(403, 'New accounts are disabled')
                if current == 'invite' and (not isinstance(email, str) or not invite_ok(email)):
                    return self._deny(403, 'This email is not approved for registration')
            else:
                if not isinstance(email, str) or not email or len(email) > 254:
                    return self._deny(503, 'Cannot check new-login policy')
                if blocked_for_email(email):
                    return self._deny(403, 'New sign-in is disabled for this account')
        except (OSError, ValueError, TypeError, KeyError, OverflowError, pymysql.MySQLError):
            return self._deny(503, 'Account access policy unavailable')
        self._forward(data)

    def log_message(self, fmt, *args):
        # No emails, query strings, passwords, request bodies or credentials in logs.
        print('Account gate: request completed', flush=True)


if __name__ == '__main__':
    print('Firefox Account & Sync account gate v0.5.6 started', flush=True)
    ThreadingHTTPServer(('0.0.0.0', 8090), Handler).serve_forever()
