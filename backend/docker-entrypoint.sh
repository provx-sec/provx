#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Apply migrations before serving. The schema is owned by Alembic, never by create_all, so
# a fresh `docker compose up` reaches a known-good schema by the same path production does.
set -eu

echo "provx: applying database migrations"
alembic upgrade head

exec "$@"
