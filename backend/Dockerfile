# SPDX-License-Identifier: Apache-2.0
# Provx backend — builds and runs independently of the rest of the monorepo.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install fastapi "uvicorn[standard]"

# Application code.
COPY app ./app

EXPOSE 8000

# Reload is convenient for the skeleton stage; drop --reload for production images.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
