"""One-shot startup inside Docker, not an external host prerequisite.
Generate FxA's OWN OAuth client and scoped-key config from upstream ytt templates.
This does not generate or replace docker-compose.yml, whose services are fixed.
"""
import copy
import os
from pathlib import Path
import subprocess
import yaml

SRC = Path('/opt/selfhost')
OUT = Path('/generated')


def need(key):
    v = os.environ.get(key, '').strip()
    if not v:
        raise RuntimeError(f'{key} fehlt in der .env')
    return v


def main():
    domain = need('FXA_BASE_DOMAIN').lower()
    if any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in domain) or domain.startswith('.') or '/' in domain:
        raise RuntimeError('FXA_BASE_DOMAIN muss ein gueltiger Hostname ohne Schema sein')
    sample = yaml.safe_load((SRC / 'config.yml.sample').read_text(encoding='utf-8'))
    config = copy.deepcopy(sample)
    config['domain'].update({'name': domain, 'content': 'accounts', 'auth': 'api',
                             'oauth': 'oauth', 'profile': 'profile', 'sync': 'sync'})
    config['fxa_version'] = need('FXA_VERSION')
    config['option']['channelserver']['enable'] = False  # kein Mozilla-Pairing-Fallback
    config['option']['admin']['enable'] = False  # separater Statusmanager, kein unsicheres FxA-Adminpanel
    config['mail']['type'] = '3rd'
    config['mail'].update({'smtp_host': 'mailpit', 'smtp_port': 1025, 'smtp_user': 'local',
                           'smtp_pass': 'local', 'smtp_secure': False,
                           'smtp_sender': f'Firefox Sync <noreply@{domain}>'})
    config['secrets'].update({'authsecret': need('FXA_AUTH_SECRET'),
                              'flowidkey': need('FXA_FLOW_KEY'),
                              'profileserver_authsecret_bearertoken': need('FXA_PROFILE_SECRET')})
    OUT.mkdir(parents=True, exist_ok=True)
    values = OUT / 'config.yml'
    values.write_text('#@data/values\n---\n' + yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding='utf-8')
    for rel, target in [('_init/auth/oauthserver-prod.tmpl.yml', 'oauthserver-prod.json'),
                        ('_init/content/contentserver-prod.tmpl.yml', 'contentserver-prod.json')]:
        with (OUT / target).open('w', encoding='utf-8') as handle:
            subprocess.run(['/usr/local/bin/ytt', '-f', str(values), '-f', str(SRC / rel), '-o', 'json'],
                           check=True, stdout=handle)
    # MySQL init files are run by the MySQL image only when fxa_db_data is empty.
    pw = need('FXA_DB_PASSWORD')
    if not pw.isalnum():
        raise RuntimeError('FXA_DB_PASSWORD nur a-z, A-Z, 0-9 (MySQL SQL-Erstinitialisierung)')
    init = "\n".join([f'CREATE DATABASE IF NOT EXISTS `{db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;' for db in ('fxa', 'fxa_oauth', 'fxa_profile', 'pushbox')])
    init += '\n' + '\n'.join([f"GRANT ALL PRIVILEGES ON `{db}`.* TO 'fxa'@'%';" for db in ('fxa','fxa_oauth','fxa_profile','pushbox')]) + '\n'
    (OUT / '01-fxa.sql').write_text(init, encoding='utf-8')
    (OUT / 'UPSTREAM_COMMIT').write_text(Path('/opt/SOURCE_COMMIT').read_text(), encoding='utf-8')
    print('FxA Konfigurationsdateien erstellt: OAuth-Clients, Content-Server, MySQL-Init; Quelle ' + (OUT / 'UPSTREAM_COMMIT').read_text().strip())
    print('FxA Logins muessen separat in einem frischen Firefox-Profil getestet werden. Keine Passwoerter in Logs.')


if __name__ == '__main__':
    main()
