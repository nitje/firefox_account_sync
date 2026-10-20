FROM golang:1.24-alpine AS build
WORKDIR /src
COPY main.go ./main.go
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /restore-admin ./main.go

FROM mysql:8.4
USER root
# mysql:8.4 already contains mysql/mysqldump, gzip and coreutils-single.
# Do NOT install full coreutils (conflicts with coreutils-single on Oracle Linux 9).
RUN set -eux; \
    microdnf install -y tar; \
    microdnf clean all; \
    for tool in mysql mysqldump tar gzip sha256sum; do command -v "$tool"; done
COPY --from=build /restore-admin /usr/local/bin/restore-admin
RUN chmod 0555 /usr/local/bin/restore-admin
USER 0:0
EXPOSE 8092
CMD ["/usr/local/bin/restore-admin"]
