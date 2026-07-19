# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Passive security-headers adapter.

Reports response headers a target fails to send. Egress goes through
``provx_sdk.fetch.fetch_within_scope`` rather than an HTTP client owned here, so scope is
enforced on every redirect hop and there is one auditable place where the network is
touched (rule PX-EGRESS).

Passive by construction (rule PX-PASSIVE): reads only, no target state is created,
modified, or deleted, and nothing here is intrusive or exploitative.

The ruleset below is fixed and ordered, so the same response always yields the same
findings in the same order (rule PX-DETERMINISM). Parsing is separated from fetching:
:meth:`parse_output` is pure, which is what lets a recorded fixture drive it in CI
(rule PX-FIXTURE).
"""

from __future__ import annotations

import json
from typing import Any, Final

from provx_sdk.fetch import FetchOutcome, fetch_within_scope
from provx_sdk.findings import Confidence, Evidence, FindingDraft, Module, Severity
from provx_sdk.scope import ScopePolicy

#: Reconnaissance of a target's exposed configuration.
RECON_TECHNIQUE: Final = "T1595"


class HeaderRule:
    """One missing-header check: what to look for and how to describe its absence."""

    __slots__ = ("header", "title", "severity", "cvss", "remediation")

    def __init__(
        self, header: str, title: str, severity: Severity, cvss: float, remediation: str
    ) -> None:
        self.header = header
        self.title = title
        self.severity = severity
        self.cvss = cvss
        self.remediation = remediation


RULES: Final[tuple[HeaderRule, ...]] = (
    HeaderRule(
        "content-security-policy",
        "Missing Content-Security-Policy header",
        Severity.LOW,
        3.1,
        "Set a Content-Security-Policy restricting script, style, and frame sources to "
        "trusted origins, starting from `default-src 'self'`.",
    ),
    HeaderRule(
        "x-frame-options",
        "Missing X-Frame-Options header",
        Severity.LOW,
        3.1,
        "Set `X-Frame-Options: DENY` (or a CSP `frame-ancestors` directive) so the page "
        "cannot be framed by another origin.",
    ),
    HeaderRule(
        "strict-transport-security",
        "Missing Strict-Transport-Security header",
        Severity.LOW,
        3.7,
        "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` so browsers "
        "refuse to downgrade to plaintext HTTP.",
    ),
    HeaderRule(
        "x-content-type-options",
        "Missing X-Content-Type-Options header",
        Severity.LOW,
        2.4,
        "Set `X-Content-Type-Options: nosniff` to stop browsers guessing content types.",
    ),
    HeaderRule(
        "referrer-policy",
        "Missing Referrer-Policy header",
        Severity.LOW,
        2.4,
        "Set `Referrer-Policy: strict-origin-when-cross-origin` to limit URL leakage to "
        "third parties.",
    ),
)


def encode_response(
    target: str,
    status_code: int,
    headers: dict[str, str],
    *,
    final_url: str | None = None,
    redirect_chain: list[str] | None = None,
    stopped_reason: str | None = None,
) -> str:
    """Serialize a probed response into the adapter's stable raw-output envelope.

    Carries both the URL requested and the URL that answered. Findings are attributed to
    ``final_url``, and the seal is taken over this whole envelope, so a hash can never
    vouch for headers a host did not send (rule PX-EVIDENCE).

    Header names are lowercased on the way in, so a fixture recorded from one server
    matches a live response from another. ``sort_keys`` keeps the encoding deterministic.
    """
    payload = {
        "target": target,
        "final_url": final_url or target,
        "redirect_chain": list(redirect_chain or [target]),
        "stopped_reason": stopped_reason,
        "status_code": status_code,
        "headers": {name.lower(): value for name, value in headers.items()},
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def encode_outcome(outcome: FetchOutcome) -> str:
    """Serialize a scope-enforced fetch outcome into the raw-output envelope."""
    return encode_response(
        outcome.requested_url,
        outcome.status_code,
        outcome.headers,
        final_url=outcome.final_url,
        redirect_chain=outcome.redirect_chain,
        stopped_reason=outcome.stopped_reason,
    )


class SecurityHeadersAdapter:
    """Reports security response headers a target fails to send."""

    name = "security_headers"
    category = "web"
    safety = "passive"
    # The Protocol documents `tool` as the external binary an adapter wraps. This one wraps
    # no binary; it names the HTTP stack instead. Widening the field's meaning is a Protocol
    # change and is left for when a second in-process adapter makes the case (audit SDK-049).
    tool = "httpx"

    def build_command(self, *, targets: list[str], use_cases: list[str]) -> list[str]:
        """Not applicable: this adapter probes in-process rather than shelling out.

        The subprocess path stays on the interface for the tools that need it - copyleft
        binaries may only ever be invoked as separate processes (rule PX-LICENSE).
        """
        raise NotImplementedError(
            "security_headers probes in-process with httpx; it has no subprocess form"
        )

    async def probe(self, target: str, *, policy: ScopePolicy, timeout: float = 10.0) -> str:
        """Fetch the target within engagement scope and return the raw-output envelope.

        ``policy`` is required rather than assumed: the scope contract is part of the
        signature, so an adapter cannot reach the network without one (rule PX-SCOPE).
        Redirects are re-checked hop by hop - see ``provx_sdk.fetch``.
        """
        outcome = await fetch_within_scope(target, policy, timeout=timeout)
        return encode_outcome(outcome)

    def parse_output(self, raw: str) -> list[FindingDraft]:
        """Normalize a raw-output envelope into one draft per missing header."""
        payload: Any = json.loads(raw)
        # Attributed to the host that actually answered, not the one that was asked; after a
        # redirect those differ, and the finding describes headers the responder sent.
        target = str(payload.get("final_url") or payload["target"])
        headers: dict[str, str] = {
            str(name).lower(): str(value) for name, value in payload["headers"].items()
        }

        drafts: list[FindingDraft] = []
        for rule in RULES:
            if headers.get(rule.header, "").strip():
                continue
            drafts.append(
                FindingDraft(
                    title=rule.title,
                    target=target,
                    module=Module.WEB,
                    severity=rule.severity,
                    cvss=rule.cvss,
                    confidence=Confidence.HIGH,
                    attack_techniques=[RECON_TECHNIQUE],
                    remediation=rule.remediation,
                    evidence=Evidence(
                        tool_output=raw,
                        matched_rule=f"{self.name}:{rule.header}",
                        reproduction_cmd=f"curl -sSI {target}",
                    ),
                )
            )
        return drafts
