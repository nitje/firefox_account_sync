FROM python:3.12-alpine
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv/gate
COPY app.py /srv/gate/app.py
RUN pip install --no-cache-dir PyMySQL==1.1.1 && chmod 0755 /srv /srv/gate && chmod 0644 /srv/gate/app.py && \
    mkdir -p /manager-state && chown 65532:65532 /manager-state && \
    python -m py_compile /srv/gate/app.py
USER 65532:65532
EXPOSE 8090
CMD ["python", "-u", "/srv/gate/app.py"]
