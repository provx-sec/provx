# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Passive well-known security.txt adapter.

Checks whether a target publishes a usable ``/.well-known/security.txt`` (RFC 9116) - the
standard channel for reporting vulnerabilities. Reports its absence, and the case where the
file is served but is not a parseable security.txt (which also catches a soft-404 that answers
200 with an HTML page).

This adapter fetches an *additional* path, so - like every other check - it goes through
``provx_sdk.fetch.fetch_within_scope`` for that path. Scope is re-checked on the security.txt
URL before it is requested (same host as the target, so it stays in scope), keeping egress on
the one auditable boundary rather than opening a second path (rules PX-EGRESS, PX-SCOPE).

Passive by construction (rule PX-PASSIVE): it issues an ordinary GET for a well-known path and
creates, modifies, or deletes no target state.

A present, parseable security.txt is the healthy baseline and yields no finding - the adapter
reports only problems, so a clean target scores zero (rule PX-FIXTURE). The verdict is decided
from the recorded envelope, so the same input always yields the same finding
(rule PX-DETERMINISM); :meth:`parse_output` is pure.
"""

from __future__ import annotations

import json
from typing import Any, Final
from urllib.parse import urljoin

from provx_sdk.fetch import FetchOutcome, fetch_within_scope
from provx_sdk.findings import Confidence, Evidence, FindingDraft, Module, Severity
from provx_sdk.scope import ScopePolicy

#: Gather Victim Org Information: security.txt is the org's published vulnerability-report
#: contact; without a usable one, coordinated disclosure has no advertised channel.
DISCLOSURE_TECHNIQUE: Final = "T1591"

SECURITY_TXT_PATH: Final = "/.well-known/security.txt"
#: RFC 9116 requires a Contact field; its presence is the minimum test of "parseable".
REQUIRED_FIELD: Final = "contact:"


class WellKnownRule:
    """One security.txt check: its stable id, how to describe it, and how to weight it."""

    __slots__ = ("check", "title", "severity", "cvss", "remediation")

    def __init__(
        self, check: str, title: str, severity: Severity, cvss: float, remediation: str
    ) -> None:
        self.check = check
        self.title = title
        self.severity = severity
        self.cvss = cvss
        self.remediation = remediation


RULES: Final[dict[str, WellKnownRule]] = {
    rule.check: rule
    for rule in (
        WellKnownRule(
            "security-txt-missing",
            "No /.well-known/security.txt is published",
            Severity.LOW,
            3.1,
            "Publish a security.txt at `/.well-known/security.txt` (RFC 9116) with at least a "
            "`Contact:` and an `Expires:` field so vulnerabilities can be reported to you.",
        ),
        WellKnownRule(
            "security-txt-unparseable",
            "/.well-known/security.txt is served but is not a valid security.txt",
            Severity.LOW,
            2.6,
            "Serve a security.txt whose body follows RFC 9116 - a `Contact:` field is "
            "mandatory. A 200 response with an HTML page (a soft 404) does not count.",
        ),
    )
}


def encode_wellknown(
    target: str,
    status_code: int,
    body: str,
    *,
    security_txt_url: str,
) -> str:
    """Serialize a probed security.txt into the adapter's stable raw-output envelope.

    Carries ``security_txt_url`` - the URL that actually answered - so findings and the seal
    attest to the resource inspected (rule PX-EVIDENCE). ``sort_keys`` keeps the encoding
    deterministic, so a fixture matches a live response byte for byte.
    """
    payload = {
        "target": target,
        "security_txt_url": security_txt_url,
        "status_code": status_code,
        "body": body,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def encode_outcome(target: str, outcome: FetchOutcome) -> str:
    """Serialize a scope-enforced fetch of the security.txt path into the raw envelope."""
    return encode_wellknown(
        target,
        outcome.status_code,
        outcome.body,
        security_txt_url=outcome.final_url,
    )


def _is_parseable_security_txt(body: str) -> bool:
    """Whether the body is a security.txt with the RFC 9116-mandatory Contact field.

    Matched line-by-line rather than as a substring so an HTML page that merely mentions the
    word (a soft 404) is not mistaken for a valid file.
    """
    return any(line.strip().lower().startswith(REQUIRED_FIELD) for line in body.splitlines())


class WellKnownAdapter:
    """Reports a missing or unparseable /.well-known/security.txt (RFC 9116)."""

    name = "wellknown"
    category = "web"
    safety = "passive"
    # As with security_headers, `tool` names the stack rather than a wrapped binary: this
    # adapter fetches a well-known path in-process with httpx (audit SDK-049).
    tool = "httpx"

    def build_command(self, *, targets: list[str], use_cases: list[str]) -> list[str]:
        """Not applicable: this adapter probes in-process rather than shelling out.

        The subprocess path stays on the interface for the tools that need it - copyleft
        binaries may only ever be invoked as separate processes (rule PX-LICENSE).
        """
        raise NotImplementedError(
            "wellknown fetches /.well-known/security.txt in-process with httpx; it has no "
            "subprocess form"
        )

    async def probe(self, target: str, *, policy: ScopePolicy, timeout: float = 10.0) -> str:
        """Fetch ``/.well-known/security.txt`` for the target's host, within scope.

        The extra path is resolved against ``target`` and fetched through the same scoped
        boundary, which re-checks scope before the request (rules PX-EGRESS, PX-SCOPE). The
        body is needed to tell a real security.txt from a soft 404, so it rides on the fetch
        already made rather than a second request.
        """
        security_txt_url = urljoin(target, SECURITY_TXT_PATH)
        outcome = await fetch_within_scope(security_txt_url, policy, timeout=timeout)
        return encode_outcome(target, outcome)

    def parse_output(self, raw: str) -> list[FindingDraft]:
        """Normalize a raw-output envelope into at most one security.txt draft."""
        payload: Any = json.loads(raw)
        target = str(payload.get("security_txt_url") or payload["target"])
        status_code = int(payload["status_code"])
        body = str(payload.get("body", ""))

        check = self._fired_check(status_code, body)
        if check is None:
            return []
        return [self._draft(RULES[check], target, raw)]

    def _fired_check(self, status_code: int, body: str) -> str | None:
        if status_code != 200:
            return "security-txt-missing"
        if not _is_parseable_security_txt(body):
            return "security-txt-unparseable"
        return None

    def _draft(self, rule: WellKnownRule, target: str, raw: str) -> FindingDraft:
        return FindingDraft(
            title=rule.title,
            target=target,
            module=Module.WEB,
            severity=rule.severity,
            cvss=rule.cvss,
            confidence=Confidence.HIGH,
            attack_techniques=[DISCLOSURE_TECHNIQUE],
            remediation=rule.remediation,
            evidence=Evidence(
                tool_output=raw,
                matched_rule=f"{self.name}:{rule.check}",
                reproduction_cmd=f"curl -sSI {target}",
            ),
        )
