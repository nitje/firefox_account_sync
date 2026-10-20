FROM python:3.12-alpine
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/backup-admin
COPY app.py /srv/backup-admin/app.py
RUN chmod 0755 /srv /srv/backup-admin && chmod 0644 /srv/backup-admin/app.py \
    && python -c "import ast,pathlib; ast.parse(pathlib.Path('/srv/backup-admin/app.py').read_text())"
# Root is confined to ./backups bind-mount; no other project files, DB or
# Docker socket mounted. Manager stays unprivileged with no backup RW mount.
USER 0:0
EXPOSE 8091
CMD ["python", "-u", "/srv/backup-admin/app.py"]
