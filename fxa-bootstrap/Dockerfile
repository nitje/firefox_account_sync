FROM python:3.12-alpine
ARG SELFHOST_REF=master
ARG YTT_VERSION=v0.52.2
RUN apk add --no-cache git curl ca-certificates && pip install --no-cache-dir PyYAML==6.0.2 && \
    git clone --depth 1 --branch "$SELFHOST_REF" https://github.com/jackyzy823/fxa-selfhosting.git /opt/selfhost && \
    git -C /opt/selfhost rev-parse HEAD > /opt/SOURCE_COMMIT && \
    curl -fLsS --retry 3 "https://github.com/carvel-dev/ytt/releases/download/${YTT_VERSION}/ytt-linux-amd64" -o /usr/local/bin/ytt && \
    echo '76d5355a5135c59a1791f420f3094579f775cbf2a987328f920a05e1338f1e1f  /usr/local/bin/ytt' | sha256sum -c - && \
    chmod 0755 /usr/local/bin/ytt
COPY generate.py /opt/generate.py
RUN chmod 0644 /opt/generate.py && python -m py_compile /opt/generate.py
CMD ["python", "-u", "/opt/generate.py"]
