# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
HTML report rendering.

Autoescaping is mandatory here: titles and targets come from scan output, which is
attacker-influenced (rule S-06). PDF and branded output are later phases; this renders the
one format the walking skeleton needs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from provx_sdk.findings import Finding

from app.models.tables import Engagement

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
REPORT_TEMPLATE = "report.html.j2"


@lru_cache(maxsize=1)
def get_environment() -> Environment:
    """Return the Jinja environment used for reports, with autoescaping enabled."""
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(default=True, default_for_string=True),
    )


def render_report(engagement: Engagement, findings: list[Finding]) -> str:
    """Render an engagement's findings into a standalone HTML report."""
    template = get_environment().get_template(REPORT_TEMPLATE)
    return template.render(
        engagement=engagement,
        findings=findings,
        generated_at=datetime.now(UTC),
    )
