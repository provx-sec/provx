# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Provx backend - FastAPI entrypoint.

This is the walking skeleton's control plane: create an engagement, run one passive
adapter within scope, read the findings, render the report. Authentication, the workflow
engine, Active mode, and exploitation are later phases (see docs/ROADMAP.md §3-5).

**No AI runs here.** Every value the API returns is produced deterministically
(rule PX-AI-OPTIONAL).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse

from app import __version__
from app.api.engagements import router as engagements_router
from app.api.schemas import ErrorResponse
from app.config import get_settings

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Provx API",
    version=__version__,
    description="Governed automated security validation - control plane.",
)
app.include_router(engagements_router)


@app.exception_handler(HTTPException)
async def handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
    """Return handled errors in the stable error envelope."""
    detail: Any = exc.detail
    if isinstance(detail, dict) and "error_code" in detail:
        body = ErrorResponse(**detail)
    else:
        body = ErrorResponse(error_code="http_error", message=str(detail))
    return JSONResponse(status_code=exc.status_code, content=body.model_dump())


@app.exception_handler(Exception)
async def handle_unexpected_exception(request: Request, exc: Exception) -> JSONResponse:
    """Log the real failure server-side and hand the client a generic message.

    Internal detail is attached only in a development environment (rules PX-ERRORS,
    B-FA-06, S-13) - in production the client learns nothing about what broke.
    """
    logger.exception("unhandled error serving %s %s", request.method, request.url.path)
    settings = get_settings()
    body = ErrorResponse(
        error_code="internal_error",
        message="Something went wrong. Please try again or contact your administrator.",
        detail=repr(exc) if settings.is_debug_env else None,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=body.model_dump()
    )


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    """Liveness probe used by Docker Compose and CI smoke tests."""
    return {"status": "ok", "service": "provx-backend", "version": __version__}


@app.get("/", tags=["meta"])
def root() -> dict[str, str]:
    return {
        "name": "Provx",
        "message": "Provx API. See /docs for the interactive API browser.",
    }
