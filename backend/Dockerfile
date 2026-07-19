# SPDX-License-Identifier: Apache-2.0
# Provx backend. Build context is the repo ROOT, not backend/, because the image needs the
# provx-sdk package from packages/adapters (see docker-compose.yml).
# Pinned to an exact patch release. Not @sha256-pinned: a digest has to be re-resolved by
# hand on every base bump and pins a single architecture, which breaks arm64/amd64 parity
# between dev machines and CI. Revisit as a pre-1.0 supply-chain hardening step.
FROM python:3.12.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install the pinned dependency set first for reproducible builds and better layer caching.
COPY backend/requirements.lock ./
RUN pip install --upgrade pip && pip install -r requirements.lock

# The SDK carries the Finding contract, the scope policy, and the adapter entry points.
# Installed as a real package so importlib.metadata can discover the adapters.
COPY packages/adapters /opt/provx-sdk
RUN pip install --no-deps /opt/provx-sdk

# Application code.
COPY backend/pyproject.toml backend/alembic.ini ./
COPY backend/alembic ./alembic
COPY backend/app ./app
COPY backend/docker-entrypoint.sh /usr/local/bin/provx-entrypoint
RUN chmod +x /usr/local/bin/provx-entrypoint

# Drop root: run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)"]

ENTRYPOINT ["provx-entrypoint"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
