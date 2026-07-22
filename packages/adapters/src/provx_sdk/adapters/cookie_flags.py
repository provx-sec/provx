# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Passive cookie-flags adapter.

Reports cookies a target sets without the protective attributes ``Secure``, ``HttpOnly``, or
``SameSite``. Egress goes through ``provx_sdk.fetch.fetch_within_scope`` rather than a client
owned here, so scope is enforced at the one auditable boundary (rule PX-EGRESS). The individual
``Set-Cookie`` values come from ``FetchOutcome.set_cookies``: the flattened ``headers`` dict
comma-merges duplicate headers, which is lossy and unsafe for cookies (a comma is legal inside
an ``Expires`` date).

Passive by construction (rule PX-PASSIVE): it reads the response's ``Set-Cookie`` headers and
creates, modifies, or deletes no target state.

The checks below are fixed and ordered and every verdict is decided from the recorded envelope,
so the same input always yields the same findings in the same order (rule PX-DETERMINISM).
Parsing is separated from probing: :meth:`parse_output` is pure, which is what lets a recorded
fixture drive it in CI (rule PX-FIXTURE).
"""

from __future__ import annotations

import json
from typing import Any, Final

from provx_sdk.fetch import FetchOutcome, fetch_within_scope
from provx_sdk.findings import Confidence, Evidence, FindingDraft, Module, Severity
from provx_sdk.scope import ScopePolicy

#: Steal Web Session Cookie: a cookie without protective flags is easier to capture or replay.
SESSION_THEFT_TECHNIQUE: Final = "T1539"
#: Browser Session Hijacking: a script-readable cookie can be lifted from a compromised page.
SESSION_HIJACK_TECHNIQUE: Final = "T1185"


class CookieRule:
    """One missing-attribute check: how to detect it, describe it, and weight it."""

    __slots__ = (
        "check",
        "attribute",
        "title_template",
        "severity",
        "cvss",
        "techniques",
        "remediation",
    )

    def __init__(
        self,
        check: str,
        attribute: str,
        title_template: str,
        severity: Severity,
        cvss: float,
        techniques: list[str],
        remediation: str,
    ) -> None:
        self.check = check
        self.attribute = attribute
        self.title_template = title_template
        self.severity = severity
        self.cvss = cvss
        self.techniques = techniques
        self.remediation = remediation


RULES: Final[tuple[CookieRule, ...]] = (
    CookieRule(
        "secure-missing",
        "secure",
        "Cookie '{name}' is set without the Secure flag",
        Severity.MEDIUM,
        5.3,
        [SESSION_THEFT_TECHNIQUE],
        "Add the `Secure` attribute so the cookie is never sent over plaintext HTTP where it "
        "could be captured in transit.",
    ),
    CookieRule(
        "httponly-missing",
        "httponly",
        "Cookie '{name}' is set without the HttpOnly flag",
        Severity.MEDIUM,
        5.3,
        [SESSION_THEFT_TECHNIQUE, SESSION_HIJACK_TECHNIQUE],
        "Add the `HttpOnly` attribute so client-side script cannot read the cookie, limiting "
        "what a cross-site-scripting flaw can steal.",
    ),
    CookieRule(
        "samesite-missing",
        "samesite",
        "Cookie '{name}' is set without a SameSite attribute",
        Severity.LOW,
        4.3,
        [SESSION_THEFT_TECHNIQUE],
        "Set `SameSite=Lax` (or `Strict`) so the cookie is not sent on cross-site requests, "
        "reducing cross-site request-forgery exposure.",
    ),
)


def encode_cookies(
    target: str,
    status_code: int,
    set_cookies: list[str],
    *,
    final_url: str | None = None,
) -> str:
    """Serialize probed cookies into the adapter's stable raw-output envelope.

    Carries the URL that answered (``final_url``) so findings and the seal attest to the host
    that actually set the cookies, not the one asked (rule PX-EVIDENCE). ``sort_keys`` keeps
    the encoding deterministic, so a fixture matches a live response byte for byte.
    """
    payload = {
        "target": target,
        "final_url": final_url or target,
        "status_code": status_code,
        "set_cookies": list(set_cookies),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def encode_outcome(outcome: FetchOutcome) -> str:
    """Serialize a scope-enforced fetch outcome into the raw-output envelope."""
    return encode_cookies(
        outcome.requested_url,
        outcome.status_code,
        outcome.set_cookies,
        final_url=outcome.final_url,
    )


def parse_cookie(set_cookie: str) -> tuple[str, set[str]]:
    """Split a ``Set-Cookie`` value into its cookie name and the set of attribute keys.

    Only the attribute *keys* are needed (``Secure``, ``HttpOnly``, ``SameSite``), lowercased
    so matching is case-insensitive. The cookie's value is deliberately not retained - it may
    be session material we must never log or seal (rule PX-SECRETS).
    """
    segments = [segment.strip() for segment in set_cookie.split(";")]
    name = segments[0].split("=", 1)[0].strip() if segments else ""
    attributes = {segment.split("=", 1)[0].strip().lower() for segment in segments[1:] if segment}
    return name, attributes


class CookieFlagsAdapter:
    """Reports cookies a target sets without Secure, HttpOnly, or SameSite."""

    name = "cookie_flags"
    category = "web"
    safety = "passive"
    # As with security_headers, `tool` names the stack rather than a wrapped binary: this
    # adapter reads Set-Cookie headers in-process with httpx (audit SDK-049).
    tool = "httpx"

    def build_command(self, *, targets: list[str], use_cases: list[str]) -> list[str]:
        """Not applicable: this adapter probes in-process rather than shelling out.

        The subprocess path stays on the interface for the tools that need it - copyleft
        binaries may only ever be invoked as separate processes (rule PX-LICENSE).
        """
        raise NotImplementedError(
            "cookie_flags reads Set-Cookie headers in-process with httpx; it has no subprocess form"
        )

    async def probe(self, target: str, *, policy: ScopePolicy, timeout: float = 10.0) -> str:
        """Fetch the target within engagement scope and return the raw-output envelope.

        ``policy`` is required rather than assumed: the scope contract is part of the
        signature, so an adapter cannot reach the network without one (rule PX-SCOPE).
        """
        outcome = await fetch_within_scope(target, policy, timeout=timeout)
        return encode_outcome(outcome)

    def parse_output(self, raw: str) -> list[FindingDraft]:
        """Normalize a raw-output envelope into one draft per deficient (cookie, attribute).

        Detection is separated from emission so the output order is stable: cookies in the
        order the response set them, and within each cookie the fixed ``RULES`` order
        (rule PX-DETERMINISM).
        """
        payload: Any = json.loads(raw)
        target = str(payload.get("final_url") or payload["target"])
        drafts: list[FindingDraft] = []
        for set_cookie in payload.get("set_cookies") or []:
            name, attributes = parse_cookie(str(set_cookie))
            for rule in RULES:
                if rule.attribute not in attributes:
                    drafts.append(self._draft(rule, name, target, raw))
        return drafts

    def _draft(self, rule: CookieRule, name: str, target: str, raw: str) -> FindingDraft:
        return FindingDraft(
            title=rule.title_template.format(name=name),
            target=target,
            module=Module.WEB,
            severity=rule.severity,
            cvss=rule.cvss,
            confidence=Confidence.HIGH,
            attack_techniques=list(rule.techniques),
            remediation=rule.remediation,
            evidence=Evidence(
                tool_output=raw,
                matched_rule=f"{self.name}:{rule.check}",
                reproduction_cmd=f"curl -sSI {target}",
            ),
        )
