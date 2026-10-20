FROM mysql:8.4
USER root
# mysql:8.4 already includes coreutils-single, gzip and findutils.
# Installing full coreutils conflicts with coreutils-single on Oracle Linux 9.
# Only tar must be installed; verify EVERY command the backup script needs.
RUN set -eux; \
    microdnf install -y tar; \
    microdnf clean all; \
    for tool in mysqldump tar gzip sha256sum find mktemp; do command -v "$tool"; done
COPY run.sh /opt/backup/run.sh
RUN chmod 0555 /opt/backup/run.sh
