"""Reversible NEW-LOGIN rule per FxA account UID.

This does not revoke existing sessions, OAuth refresh tokens, or Sync tokens.
Never modify Mozilla's database or its account lifecycle state here.
"""
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone

STATE_DIR = os.environ.get('MANAGER_STATE_DIR', '/manager-state')
ACCESS = os.path.join(STATE_DIR, 'login-blocks.json')
AUDIT = os.path.join(STATE_DIR, 'audit.jsonl')
UID = re.compile(r'^[0-9A-F]{32}$')
_LOCK = threading.RLock()


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def read_blocks():
    """Missing state = no blocks (upgrade-safe); invalid/unreadable = fail closed."""
    try:
        with open(ACCESS, encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict) or data.get('version') != 1 or not isinstance(data.get('blocked_uids'), dict):
        raise ValueError('Ungueltiger Neuanmeldungsstatus')
    result = data['blocked_uids']
    if len(result) > 20000:
        raise ValueError('Zu viele Sperreintraege')
    for uid, entry in result.items():
        if not UID.fullmatch(uid) or not isinstance(entry, dict) or not isinstance(entry.get('at'), str):
            raise ValueError('Ungueltiger Sperreintrag')
    return result


def change_login(uid, blocked, actor):
    if not isinstance(uid, str) or not UID.fullmatch(uid):
        raise ValueError('Ungueltige UID')
    if type(blocked) is not bool:
        raise ValueError('Ungueltiger Sperrstatus')
    with _LOCK:
        current = dict(read_blocks())
        if blocked:
            current[uid] = {'at': now()}
        else:
            current.pop(uid, None)
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', prefix='.login-blocks-', dir=STATE_DIR, delete=False) as f:
                tmp = f.name
                os.fchmod(f.fileno(), 0o600)
                json.dump({'version': 1, 'blocked_uids': current}, f, sort_keys=True)
                f.write('\n')
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, ACCESS)
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
        # Write one JSONL line without sharing thread locks across modules.
        event = json.dumps({'at': now(), 'actor': actor,
                            'action': 'new_login_blocked' if blocked else 'new_login_allowed',
                            'uid': uid}) + '\n'
        fd = os.open(AUDIT, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, event.encode('utf-8'))
            os.fsync(fd)
        finally:
            os.close(fd)
        return current
