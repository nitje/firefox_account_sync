"""Manager policy for the FxA 1.342.2 signup routes. No mutation of Mozilla account records."""
import json
import os
import threading
import tempfile
import re
from datetime import timedelta
from datetime import datetime, timezone

DIR = os.environ.get("MANAGER_STATE_DIR", "/manager-state")
STATE = os.path.join(DIR, "registration.json")
AUDIT = os.path.join(DIR, "audit.jsonl")
INVITES = os.path.join(DIR, "invitations.json")
LOCK = threading.RLock()


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_mode():
    """Legacy state v1 {enabled: bool}, v2 {mode: open|closed|invite}."""
    try:
        with open(STATE, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return "open", "Ausgangseinstellung v0.3.6: offen", None
    except (OSError, ValueError, UnicodeError):
        return "closed", "", "Managerstatus nicht lesbar – vorsorglich geschlossen"
    if not isinstance(data, dict):
        return "closed", "", "Managerstatus ungueltig – vorsorglich geschlossen"
    if data.get("version") == 2:
        if data.get("mode") in ("open", "closed", "invite"):
            return data["mode"], str(data.get("updated_at", "–")), None
        return "closed", "", "Managerstatus ungueltig – vorsorglich geschlossen"
    if type(data.get("enabled")) is bool:
        return ("open" if data["enabled"] else "closed"), str(data.get("updated_at", "–")), None
    return "closed", "", "Managerstatus ungueltig – vorsorglich geschlossen"


def mode():
    with LOCK:
        return _read_mode()


def policy():
    current, when, error = mode()
    return current == "open", when, error


def _atomic_json(path, payload):
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".state-", dir=DIR, delete=False) as f:
            tmp = f.name
            os.fchmod(f.fileno(), 0o600)
            json.dump(payload, f, ensure_ascii=True, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def _audit(actor, action):
    # Never log e-mail addresses, secrets or client input.
    with open(AUDIT, "a", encoding="utf-8") as f:
        os.chmod(AUDIT, 0o600)
        f.write(json.dumps({"at": now(), "actor": actor, "action": action}) + "\n")
        f.flush()
        os.fsync(f.fileno())


def change_mode(new_mode, actor):
    if new_mode not in ("open", "closed", "invite"):
        raise ValueError("invalid mode")
    with LOCK:
        _, _, error = _read_mode()
        if error:
            raise OSError(error)
        if new_mode == "invite":
            # Corrupt invitation list must not lead to accidental open signup.
            _read_invites()
        payload = {"version": 2, "mode": new_mode, "updated_at": now()}
        _atomic_json(STATE, payload)
        _audit(actor, "registration_" + new_mode)
        return payload


def change(enabled, actor):
    if type(enabled) is not bool:
        raise ValueError("enabled must be boolean")
    return change_mode("open" if enabled else "closed", actor)


# The signup gate and manager share this versioned, owner-only JSON file.
# No "invite token" embedded in a public URL: only an explicit email allowlist.
EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")

def normalize_email(value):
    if not isinstance(value, str):
        raise ValueError("E-Mail fehlt")
    value = value.strip().lower()
    if len(value) > 254 or not EMAIL.fullmatch(value) or ".." in value or value.startswith("."):
        raise ValueError("Ungueltige E-Mail")
    return value


def _read_invites():
    try:
        with open(INVITES, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, UnicodeError) as exc:
        raise OSError("Einladungsliste nicht lesbar") from exc
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("emails"), dict):
        raise OSError("Einladungsliste ungueltig")
    emails = data["emails"]
    if len(emails) > 2000 or any(not isinstance(e, str) or not isinstance(v, dict) or
                                 not isinstance(v.get("expires_at"), str) for e,v in emails.items()):
        raise OSError("Einladungsliste ungueltig")
    return emails


def invitations():
    with LOCK:
        items = _read_invites()
        current = datetime.now(timezone.utc)
        result=[]
        for email, detail in sorted(items.items()):
            try:
                expiry = datetime.fromisoformat(detail["expires_at"])
                if expiry.tzinfo is None:
                    raise ValueError("no timezone")
                active = expiry > current
            except ValueError as exc:
                raise OSError("Ungueltiger Ablaufzeitpunkt") from exc
            result.append({"email":email, "expires_at":detail["expires_at"], "active":active})
        return result


def invite(email, days, actor):
    email = normalize_email(email)
    if not isinstance(days, int) or days < 1 or days > 90:
        raise ValueError("Gueltigkeit 1 bis 90 Tage")
    with LOCK:
        items = _read_invites()
        if len(items) >= 2000 and email not in items:
            raise ValueError("Maximal 2000 Freigaben")
        created = datetime.now(timezone.utc)
        items[email] = {"created_at": created.isoformat(timespec="seconds"),
                        "expires_at": (created + timedelta(days=days)).isoformat(timespec="seconds")}
        _atomic_json(INVITES, {"version":1,"emails":items})
        _audit(actor, "invite_added")
        return email


def revoke(email, actor):
    email = normalize_email(email)
    with LOCK:
        items = _read_invites()
        if email not in items:
            raise ValueError("Freigabe nicht gefunden")
        del items[email]
        _atomic_json(INVITES, {"version":1,"emails":items})
        _audit(actor, "invite_revoked")
        return email


def audit_entries(max_count=80):
    try:
        with open(AUDIT, encoding="utf-8") as f:
            lines = f.readlines()[-max_count:]
        return [json.loads(line) for line in reversed(lines) if line.strip()]
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        return [{"at": "–", "actor": "–", "action": "Auditdatei nicht lesbar"}]
