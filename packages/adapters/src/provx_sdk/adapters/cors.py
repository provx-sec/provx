# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Passive CORS-misconfiguration adapter.

Reports cross-origin-resource-sharing response headers that widen a target's trust boundary:
a wildcard ``Access-Control-Allow-Origin``, a wildcard combined with
``Access-Control-Allow-Credentials: true``, a ``null`` origin, and a specific origin allowed
*with* credentials. Egress goes through ``provx_sdk.fetch.fetch_within_scope`` rather than a
client owned here, so scope is enforced at the one auditable boundary (rule PX-EGRESS).

Passive by construction (rule PX-PASSIVE): it reads the CORS headers the target already
returns on an ordinary GET and creates, modifies, or deletes no target state. It deliberately
does **not** send a crafted cross-origin ``Origin`` header to test for reflection - that is an
Active-mode probe. A reflected-origin misconfiguration is therefore reported at reduced
confidence: the header combination is the signal, not a confirmed reflection.

The checks are fixed and decided from the recorded envelope, so the same input always yields
the same finding (rule PX-DETERMINISM). Parsing is separated from probing: :meth:`parse_output`
is pure, which is what lets a recorded fixture drive it in CI (rule PX-FIXTURE).
"""

from __future__ import annotations

import json
from typing import Any, Final

from provx_sdk.fetch import FetchOutcome, fetch_within_scope
from provx_sdk.findings import Confidence, Evidence, FindingDraft, Module, Severity
from provx_sdk.scope import ScopePolicy

#: Exploit Public-Facing Application: a permissive CORS policy lets another origin read data.
EXPLOIT_TECHNIQUE: Final = "T1190"
#: Steal Web Session Cookie: allowing credentials cross-origin exposes authenticated responses.
SESSION_THEFT_TECHNIQUE: Final = "T1539"

ACAO_HEADER: Final = "access-control-allow-origin"
ACAC_HEADER: Final = "access-control-allow-credentials"


class CorsRule:
    """One CORS misconfiguration: its stable id, how to describe it, and how to weight it."""

    __slots__ = ("check", "title", "severity", "cvss", "confidence", "techniques", "remediation")

    def __init__(
        self,
        check: str,
        title: str,
        severity: Severity,
        cvss: float,
        confidence: Confidence,
        techniques: list[str],
        remediation: str,
    ) -> None:
        self.check = check
        self.title = title
        self.severity = severity
        self.cvss = cvss
        self.confidence = confidence
        self.techniques = techniques
        self.remediation = remediation


RULES: Final[dict[str, CorsRule]] = {
    rule.check: rule
    for rule in (
        CorsRule(
            "wildcard-with-credentials",
            "CORS allows any origin together with credentials",
            Severity.HIGH,
            7.5,
            Confidence.HIGH,
            [EXPLOIT_TECHNIQUE, SESSION_THEFT_TECHNIQUE],
            "Never combine `Access-Control-Allow-Origin: *` with "
            "`Access-Control-Allow-Credentials: true`. Echo only an explicit allowlist of "
            "trusted origins, and send credentials to those alone.",
        ),
        CorsRule(
            "wildcard-origin",
            "CORS allows requests from any origin",
            Severity.MEDIUM,
            5.3,
            Confidence.HIGH,
            [EXPLOIT_TECHNIQUE],
            "Replace `Access-Control-Allow-Origin: *` with an explicit allowlist of the "
            "origins that legitimately need cross-origin access.",
        ),
        CorsRule(
            "null-origin",
            "CORS allows the null origin",
            Severity.MEDIUM,
            5.8,
            Confidence.HIGH,
            [EXPLOIT_TECHNIQUE],
            "Do not return `Access-Control-Allow-Origin: null`; a sandboxed iframe or a "
            "local file can present the null origin and would be trusted.",
        ),
        CorsRule(
            "credentialed-origin",
            "CORS allows a specific origin together with credentials",
            Severity.HIGH,
            8.1,
            # Passive observation cannot tell an intended allowlist entry from a reflected,
            # attacker-controllable origin; report the combination but not as certain.
            Confidence.MEDIUM,
            [EXPLOIT_TECHNIQUE, SESSION_THEFT_TECHNIQUE],
            "Confirm the allowed origin is a fixed, trusted value and not reflected from the "
            "request. If credentials are not required cross-origin, drop "
            "`Access-Control-Allow-Credentials: true`.",
        ),
    )
}


def encode_cors(
    target: str,
    status_code: int,
    headers: dict[str, str],
    *,
    final_url: str | None = None,
) -> str:
    """Serialize probed CORS headers into the adapter's stable raw-output envelope.

    Carries the URL that answered (``final_url``) so findings and the seal attest to the host
    that actually responded (rule PX-EVIDENCE). Header names are lowercased and ``sort_keys``
    keeps the encoding deterministic, so a fixture matches a live response byte for byte.
    """
    payload = {
        "target": target,
        "final_url": final_url or target,
        "status_code": status_code,
        "headers": {name.lower(): value for name, value in headers.items()},
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def encode_outcome(outcome: FetchOutcome) -> str:
    """Serialize a scope-enforced fetch outcome into the raw-output envelope."""
    return encode_cors(
        outcome.requested_url,
        outcome.status_code,
        outcome.headers,
        final_url=outcome.final_url,
    )


def _fired_check(allow_origin: str, allow_credentials: bool) -> str | None:
    """Which single CORS rule the response headers trigger, or None for a safe policy.

    A specific allowed origin *without* credentials is an intended, common configuration and
    is not reported; only the permissive shapes are.
    """
    if not allow_origin:
        return None
    if allow_origin == "*":
        return "wildcard-with-credentials" if allow_credentials else "wildcard-origin"
    if allow_origin.lower() == "null":
        return "null-origin"
    if allow_credentials:
        return "credentialed-origin"
    return None


class CorsAdapter:
    """Reports cross-origin-resource-sharing headers that widen a target's trust boundary."""

    name = "cors"
    category = "web"
    safety = "passive"
    # As with security_headers, `tool` names the stack rather than a wrapped binary: this
    # adapter reads CORS response headers in-process with httpx (audit SDK-049).
    tool = "httpx"

    def build_command(self, *, targets: list[str], use_cases: list[str]) -> list[str]:
        """Not applicable: this adapter probes in-process rather than shelling out.

        The subprocess path stays on the interface for the tools that need it - copyleft
        binaries may only ever be invoked as separate processes (rule PX-LICENSE).
        """
        raise NotImplementedError(
            "cors reads CORS response headers in-process with httpx; it has no subprocess form"
        )

    async def probe(self, target: str, *, policy: ScopePolicy, timeout: float = 10.0) -> str:
        """Fetch the target within engagement scope and return the raw-output envelope.

        ``policy`` is required rather than assumed: the scope contract is part of the
        signature, so an adapter cannot reach the network without one (rule PX-SCOPE). No
        crafted ``Origin`` header is sent - the probe stays passive (rule PX-PASSIVE).
        """
        outcome = await fetch_within_scope(target, policy, timeout=timeout)
        return encode_outcome(outcome)

    def parse_output(self, raw: str) -> list[FindingDraft]:
        """Normalize a raw-output envelope into at most one CORS misconfiguration draft."""
        payload: Any = json.loads(raw)
        target = str(payload.get("final_url") or payload["target"])
        headers: dict[str, str] = {
            str(name).lower(): str(value) for name, value in payload["headers"].items()
        }
        allow_origin = headers.get(ACAO_HEADER, "").strip()
        allow_credentials = headers.get(ACAC_HEADER, "").strip().lower() == "true"

        check = _fired_check(allow_origin, allow_credentials)
        if check is None:
            return []
        return [self._draft(RULES[check], target, raw)]

    def _draft(self, rule: CorsRule, target: str, raw: str) -> FindingDraft:
        return FindingDraft(
            title=rule.title,
            target=target,
            module=Module.WEB,
            severity=rule.severity,
            cvss=rule.cvss,
            confidence=rule.confidence,
            attack_techniques=list(rule.techniques),
            remediation=rule.remediation,
            evidence=Evidence(
                tool_output=raw,
                matched_rule=f"{self.name}:{rule.check}",
                reproduction_cmd=f"curl -sSI {target}",
            ),
        )
