# Deployment owner must supply a digest-pinned Python base and publish a new digest.
ARG PYTHON_BASE
FROM ${PYTHON_BASE}
WORKDIR /opt/opal-model-wire
COPY model_wire.py wire_gateway.py deadline_http.py wire_deadline.py ./
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
ENTRYPOINT ["python", "/opt/opal-model-wire/wire_gateway.py"]
