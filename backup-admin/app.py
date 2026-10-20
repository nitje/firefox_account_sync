"""Private backup inventory/deletion service for Firefox Account & Sync v0.5.8.

Only completed, strictly named directory entries under /backups may be deleted.
No public port, no database credentials, no Docker socket, no /project/.env mount.
"""
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BACKUPS = os.environ.get("BACKUP_DIR", "/backups")
KEY = hashlib.sha256(b"fxa-backup-management-v1\x00" + os.environ["ADMIN_PASSWORD"].encode()).digest()
NAME = re.compile(r"^backup-([0-9]{8}T[0-9]{6}Z)(?:-([1-9][0-9]*))?$")
MAX_BACKUPS = 2000


def list_backups():
    items = []
    with os.scandir(BACKUPS) as iterator:
        for entry in iterator:
            match = NAME.fullmatch(entry.name)
            if not match or not entry.is_dir(follow_symlinks=False):
                continue
            timestamp = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            # The backup script writes to .pending-* and atomically RENAMES
            # only after all dumps, archive and SHA256SUMS are complete.
            size = 0
            with os.scandir(entry.path) as members:
                for file in members:
                    if file.is_file(follow_symlinks=False):
                        size += file.stat(follow_symlinks=False).st_size
            items.append({"name": entry.name, "date_utc": timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                          "size_bytes": size})
            if len(items) > MAX_BACKUPS:
                raise ValueError("Zu viele Sicherungen, automatische Komplettauswahl deaktiviert")
    items.sort(key=lambda item: item["name"], reverse=True)
    return items


def delete_backups(names):
    if not isinstance(names, list) or not names or len(names) > MAX_BACKUPS:
        raise ValueError("Keine/zu viele Sicherungen")
    if any(not isinstance(n, str) or not NAME.fullmatch(n) for n in names):
        raise ValueError("Ungueltiger Backup-Ordnername")
    if len(names) != len(set(names)):
        raise ValueError("Doppelte Sicherung")
    root_fd = os.open(BACKUPS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    deleted = []
    try:
        # Check every requested item before removing the first one.
        for n in names:
            info = os.stat(n, dir_fd=root_fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("Sicherung ist kein echtes Verzeichnis")
        for n in names:
            # shutil.rmtree uses fd-based symlink-attack-resistant deletion
            # on Linux. The anchored root fd prevents path traversal.
            shutil.rmtree(n, dir_fd=root_fd)
            deleted.append(n)
    finally:
        os.close(root_fd)
    return deleted


class Handler(BaseHTTPRequestHandler):
    server_version = "FirefoxBackupAdmin/0.6.0"

    def send_json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def authorized(self, method, path, body=b""):
        stamp = self.headers.get("X-Backup-Timestamp", "")
        signature = self.headers.get("X-Backup-Signature", "")
        if not stamp.isdigit() or len(stamp) != 10 or not re.fullmatch("[0-9a-f]{64}", signature):
            return False
        if abs(int(time.time()) - int(stamp)) > 90:
            return False
        message = method.encode() + b"\n" + path.encode() + b"\n" + stamp.encode() + b"\n" + body
        expected = hmac.new(KEY, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)

    def do_GET(self):
        if self.path == "/healthz":
            return self.send_json(200, {"ok": True})
        if self.path != "/list":
            return self.send_json(404, {"error": "not_found"})
        if not self.authorized("GET", "/list"):
            return self.send_json(403, {"error": "forbidden"})
        try:
            return self.send_json(200, {"backups": list_backups()})
        except (OSError, ValueError):
            return self.send_json(503, {"error": "inventory_unavailable"})

    def do_POST(self):
        if self.path != "/delete":
            return self.send_json(404, {"error": "not_found"})
        if os.path.exists("/restore-status/restore.lock"):
            return self.send_json(409, {"error": "restore_in_progress"})
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 1 or length > 131072:
            return self.send_json(413, {"error": "invalid_length"})
        body = self.rfile.read(length)
        if not self.authorized("POST", "/delete", body):
            return self.send_json(403, {"error": "forbidden"})
        try:
            value = json.loads(body)
            if not isinstance(value, dict) or set(value) != {"backups"}:
                raise ValueError("invalid_payload")
            deleted = delete_backups(value["backups"])
            print("Backup-Admin: removed", len(deleted), "completed backup directories", flush=True)
            return self.send_json(200, {"deleted": deleted})
        except (ValueError, TypeError, FileNotFoundError):
            return self.send_json(400, {"error": "invalid_selection_or_missing"})
        except OSError:
            return self.send_json(503, {"error": "delete_failed_check_folder_permissions"})

    def log_message(self, fmt, *args):
        # Do not emit backup directory names or request headers.
        print("backup-admin HTTP", args[1] if len(args) > 1 else "-", flush=True)


if __name__ == "__main__":
    print("Firefox Backup-Admin 0.6.0 (internal only) listening on 8091", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8091), Handler).serve_forever()
