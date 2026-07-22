# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Passive TLS / transport-hygiene adapter.

Reports transport weaknesses a target exposes: a missing HSTS header, an absent HTTP->HTTPS
upgrade, and - when the target answers over https - an expired or untrusted certificate and a
weak negotiated protocol. Egress goes through ``provx_sdk.fetch`` (``fetch_within_scope`` for
the HTTP facts, ``probe_tls_within_scope`` for the handshake) rather than a client or socket
owned here, so scope is enforced at the one auditable boundary (rule PX-EGRESS).

Passive by construction (rule PX-PASSIVE): it reads response headers and completes a TLS
handshake, and creates, modifies, or deletes no target state.

The ruleset below is fixed and ordered, and every verdict is decided from the recorded
envelope, so the same input always yields the same findings in the same order
(rule PX-DETERMINISM). Parsing is separated from probing: :meth:`parse_output` is pure, which
is what lets a recorded fixture drive it in CI (rule PX-FIXTURE).
"""

from __future__ import annotations

import json
from typing import Any, Final
from urllib.parse import urlsplit

from provx_sdk.adapters.security_headers import HSTS_RULE_ID
from provx_sdk.fetch import TlsHandshake, fetch_within_scope, probe_tls_within_scope
from provx_sdk.findings import Confidence, Evidence, FindingDraft, Module, Severity
from provx_sdk.scope import ScopePolicy

#: Adversary-in-the-Middle: weak transport lets an attacker sit between client and server.
AITM_TECHNIQUE: Final = "T1557"
#: Network Sniffing: cleartext or downgraded transport exposes traffic to capture.
SNIFF_TECHNIQUE: Final = "T1040"

#: Protocol versions considered weak. TLS 1.2 and 1.3 are the acceptable floor.
WEAK_PROTOCOLS: Final[frozenset[str]] = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})

HSTS_HEADER: Final = "strict-transport-security"


class TransportRule:
    """One transport check: its stable id, how to describe it, and how to weight it."""

    __slots__ = ("check", "title", "severity", "cvss", "techniques", "remediation", "rule_id")

    def __init__(
        self,
        check: str,
        title: str,
        severity: Severity,
        cvss: float,
        techniques: list[str],
        remediation: str,
        rule_id: str | None = None,
    ) -> None:
        self.check = check
        self.title = title
        self.severity = severity
        self.cvss = cvss
        self.techniques = techniques
        self.remediation = remediation
        # Canonical cross-adapter dedup id; set only where security_headers reports the same
        # issue (HSTS) so the two collapse into one finding (PX-DETERMINISM).
        self.rule_id = rule_id


RULES: Final[dict[str, TransportRule]] = {
    rule.check: rule
    for rule in (
        TransportRule(
            "no-https-redirect",
            "HTTP does not redirect to HTTPS",
            Severity.MEDIUM,
            6.5,
            [SNIFF_TECHNIQUE, AITM_TECHNIQUE],
            "Return a 301 redirect from every HTTP URL to its HTTPS equivalent so clients are "
            "never served over cleartext.",
        ),
        TransportRule(
            "hsts-missing",
            "Missing Strict-Transport-Security header",
            Severity.MEDIUM,
            5.3,
            [AITM_TECHNIQUE],
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` so browsers "
            "refuse to downgrade to plaintext HTTP.",
            rule_id=HSTS_RULE_ID,
        ),
        TransportRule(
            "cert-expired",
            "TLS certificate is expired",
            Severity.HIGH,
            7.4,
            [AITM_TECHNIQUE],
            "Renew the certificate and automate renewal so it cannot lapse; an expired "
            "certificate trains users to click through browser warnings.",
        ),
        TransportRule(
            "cert-untrusted",
            "TLS certificate does not chain to a trusted root",
            Severity.MEDIUM,
            5.3,
            [AITM_TECHNIQUE],
            "Serve a certificate issued by a trusted CA (or one the client population trusts); "
            "a self-signed or broken chain cannot be told apart from an interception attempt.",
        ),
        TransportRule(
            "weak-protocol",
            "Weak TLS protocol negotiated",
            Severity.MEDIUM,
            5.9,
            [AITM_TECHNIQUE, SNIFF_TECHNIQUE],
            "Disable SSLv3, TLS 1.0, and TLS 1.1; require TLS 1.2 or higher.",
        ),
    )
}


def handshake_to_dict(handshake: TlsHandshake) -> dict[str, Any]:
    """Flatten a TLS handshake into the JSON-serializable shape the envelope carries."""
    return {
        "protocol": handshake.protocol,
        "cipher": handshake.cipher,
        "not_after_epoch": handshake.not_after_epoch,
        "cert_error": handshake.cert_error,
        "error": handshake.error,
    }


def encode_transport(
    target: str,
    status_code: int,
    headers: dict[str, str],
    *,
    final_url: str | None = None,
    redirect_location: str | None = None,
    tls: dict[str, Any] | None = None,
) -> str:
    """Serialize a probed transport into the adapter's stable raw-output envelope.

    Carries the URL that answered (``final_url``) so findings and the seal attest to the host
    that actually responded, not the one asked (rule PX-EVIDENCE). ``tls`` is None when the
    target was not reached over https. Header names are lowercased and ``sort_keys`` keeps the
    encoding deterministic, so a fixture matches a live response byte for byte.
    """
    payload = {
        "target": target,
        "final_url": final_url or target,
        "status_code": status_code,
        "redirect_location": redirect_location,
        "headers": {name.lower(): value for name, value in headers.items()},
        "tls": tls,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


class TlsTransportAdapter:
    """Reports TLS and HTTP transport weaknesses a target exposes."""

    name = "tls"
    category = "web"
    safety = "passive"
    # As with security_headers, `tool` names the stack rather than a wrapped binary: this
    # adapter probes in-process with httpx + the stdlib ssl module (audit SDK-049).
    tool = "ssl"

    def build_command(self, *, targets: list[str], use_cases: list[str]) -> list[str]:
        """Not applicable: this adapter probes in-process rather than shelling out.

        The subprocess path stays on the interface for the tools that need it - copyleft
        binaries may only ever be invoked as separate processes (rule PX-LICENSE).
        """
        raise NotImplementedError(
            "tls probes in-process with httpx and the ssl module; it has no subprocess form"
        )

    async def probe(self, target: str, *, policy: ScopePolicy, timeout: float = 10.0) -> str:
        """Probe the target within scope and return the raw-output envelope.

        Redirects are not followed (``max_redirects=0``): the check needs to see the upgrade a
        redirect *intends*, not chase it to a host that may not answer. When the target is
        https, a scope-checked handshake adds the certificate and protocol facts (rule
        PX-SCOPE); over http there is no certificate to inspect and ``tls`` stays None.
        """
        outcome = await fetch_within_scope(target, policy, timeout=timeout, max_redirects=0)
        tls: dict[str, Any] | None = None
        if urlsplit(target).scheme == "https":
            handshake = await probe_tls_within_scope(target, policy, timeout=timeout)
            tls = handshake_to_dict(handshake)
        return encode_transport(
            outcome.requested_url,
            outcome.status_code,
            outcome.headers,
            final_url=outcome.final_url,
            redirect_location=outcome.redirect_location,
            tls=tls,
        )

    def parse_output(self, raw: str) -> list[FindingDraft]:
        """Normalize a raw-output envelope into one draft per transport weakness.

        Detection is separated from emission so the output order is the fixed ``RULES`` order
        regardless of how the checks were evaluated (rule PX-DETERMINISM).
        """
        payload: Any = json.loads(raw)
        target = str(payload.get("final_url") or payload["target"])
        fired = _fired_checks(
            scheme=urlsplit(target).scheme,
            headers={str(name).lower(): str(value) for name, value in payload["headers"].items()},
            redirect_location=payload.get("redirect_location"),
            tls=payload.get("tls"),
        )
        return [self._draft(rule, target, raw) for rule in RULES.values() if rule.check in fired]

    def _draft(self, rule: TransportRule, target: str, raw: str) -> FindingDraft:
        return FindingDraft(
            title=rule.title,
            target=target,
            module=Module.WEB,
            severity=rule.severity,
            cvss=rule.cvss,
            confidence=Confidence.HIGH,
            attack_techniques=list(rule.techniques),
            remediation=rule.remediation,
            rule_id=rule.rule_id,
            evidence=Evidence(
                tool_output=raw,
                matched_rule=f"{self.name}:{rule.check}",
                reproduction_cmd=f"curl -sSI {target}",
            ),
        )


def _fired_checks(
    *,
    scheme: str,
    headers: dict[str, str],
    redirect_location: Any,
    tls: Any,
) -> set[str]:
    """The set of rule ids the probed transport triggers."""
    fired: set[str] = set()
    if not headers.get(HSTS_HEADER, "").strip():
        fired.add("hsts-missing")
    if scheme == "http" and not _redirects_to_https(redirect_location):
        fired.add("no-https-redirect")
    fired |= _cert_checks(tls)
    return fired


def _redirects_to_https(redirect_location: Any) -> bool:
    return isinstance(redirect_location, str) and redirect_location.lower().startswith("https://")


def _cert_checks(tls: Any) -> set[str]:
    """Which certificate/protocol rules a handshake result triggers.

    A connection-level failure (``error`` set) means no certificate was seen, so nothing is
    asserted about it rather than guessing.
    """
    if not isinstance(tls, dict) or tls.get("error"):
        return set()
    fired: set[str] = set()
    cert_error = tls.get("cert_error")
    if cert_error == "expired":
        fired.add("cert-expired")
    elif cert_error in ("self_signed", "invalid"):
        fired.add("cert-untrusted")
    protocol = tls.get("protocol")
    if isinstance(protocol, str) and protocol in WEAK_PROTOCOLS:
        fired.add("weak-protocol")
    return fired
