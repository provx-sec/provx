# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Provx backend — minimal FastAPI skeleton.

This is the Phase 1 walking-skeleton entrypoint: enough to prove the service builds,
runs, and answers a health check. Engagements, scanning, the findings pipeline, and
the safety/scope engine are added in later phases (see docs/ROADMAP.md §3-5).
"""

from fastapi import FastAPI

from app import __version__

app = FastAPI(
    title="Provx API",
    version=__version__,
    description="Governed automated security validation — control plane (skeleton).",
)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    """Liveness probe used by Docker Compose and CI smoke tests."""
    return {"status": "ok", "service": "provx-backend", "version": __version__}


@app.get("/", tags=["meta"])
def root() -> dict[str, str]:
    return {
        "name": "Provx",
        "message": "Provx API skeleton. See /docs for the interactive API browser.",
    }
