FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Eigenes App-Verzeichnis: Keine Abhaengigkeit von /app oder Dateirechten
# des entpackten ZIPs bzw. des Docker-Build-Kontexts.
WORKDIR /srv/manager
COPY app.py registration.py account_access.py /srv/manager/
RUN pip install --no-cache-dir PyMySQL==1.1.1

# COPY kann lokale Dateirechte uebernehmen. Daher im IMAGE explizit
# Besitzer und Lese-/Verzeichnisrechte setzen, bevor USER aktiv wird.
RUN set -eux; \
    chmod 0755 /srv /srv/manager; \
    chown -R 65532:65532 /srv/manager; \
    chmod 0644 /srv/manager/app.py /srv/manager/registration.py /srv/manager/account_access.py; \
    mkdir -p /manager-state; chown 65532:65532 /manager-state; chmod 0700 /manager-state; \
    python -c "import ast, pathlib; [ast.parse(p.read_text(encoding='utf-8')) for p in pathlib.Path('/srv/manager').glob('*.py')]"

USER 65532:65532
EXPOSE 8080
CMD ["python", "-u", "/srv/manager/app.py"]
