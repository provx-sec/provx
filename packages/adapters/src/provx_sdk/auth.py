# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Explicit authenticated-scanning credentials (rules PX-SECRETS, PX-SCOPE).

Authenticated scanning presents an operator-supplied credential so a scan can reach pages that
would otherwise answer 401/403. Only **explicit** methods live here - a bearer token, a cookie
string, or a custom header. Form-login auto-detection, CSRF handling, SSO/MFA, and session
recording are deliberately out of scope (see docs/KNOWN_ISSUES.md).

Every method reduces to the same shape: one request header, ``(header_name, header_value)``. That
is the single thing the egress boundary injects and the single thing its redaction must cover, so
"the thing that authenticates" and "the thing that is sealed and redacted" line up by construction
(rule PX-EVIDENCE). The value is a live secret: :class:`AuthCredential` never puts it in its
``repr``, and it is only ever decrypted in memory at scan time (rule PX-SECRETS).
"""

from __future__ import annotations

from dataclasses import dataclass

#: The three explicit credential kinds this phase supports.
BEARER = "bearer"
COOKIE = "cookie"
HEADER = "header"
CREDENTIAL_TYPES: frozenset[str] = frozenset({BEARER, COOKIE, HEADER})

#: The fixed header each non-custom kind maps to.
_BEARER_HEADER = "Authorization"
_COOKIE_HEADER = "Cookie"
_BEARER_PREFIX = "Bearer "


class InvalidCredentialError(ValueError):
    """Raised when a credential's type, value, or header name is not usable."""


@dataclass(frozen=True)
class AuthCredential:
    """A normalized credential: exactly one request header to attach.

    ``__repr__`` is overridden so the secret never reaches a log line or a traceback frame
    (rule PX-SECRETS); the header *name* is safe to show and helps an operator see which control
    was applied.
    """

    header_name: str
    header_value: str

    def __repr__(self) -> str:
        return f"AuthCredential(header_name={self.header_name!r}, header_value=<redacted>)"


def resolve_header_name(cred_type: str, header_name: str | None) -> str:
    """The effective header a credential of this kind attaches to.

    Bearer and cookie map to fixed headers; a custom header carries its own name. Used both to
    store a displayable name and to build the injected header, so the two never drift.
    """
    kind = cred_type.strip().lower()
    if kind == BEARER:
        return _BEARER_HEADER
    if kind == COOKIE:
        return _COOKIE_HEADER
    if kind == HEADER:
        name = (header_name or "").strip()
        if not name:
            raise InvalidCredentialError("a custom-header credential requires a header name")
        return name
    raise InvalidCredentialError(f"unknown credential type {cred_type!r}")


def build_auth(cred_type: str, value: str, header_name: str | None = None) -> AuthCredential:
    """Normalize an explicit credential into the single header it injects.

    * ``bearer`` -> ``Authorization: Bearer <token>`` (the prefix is added only if absent, so a
      value already carrying ``Bearer `` is not doubled).
    * ``cookie`` -> ``Cookie: <cookie-string>``.
    * ``header`` -> ``<name>: <value>``.

    An empty value is refused for every kind - a blank credential is a configuration mistake, not
    an anonymous scan (which is simply the no-credential path).
    """
    kind = cred_type.strip().lower()
    if not value:
        raise InvalidCredentialError("a credential value must not be empty")

    name = resolve_header_name(kind, header_name)
    if kind == BEARER:
        header_value = value if value.startswith(_BEARER_PREFIX) else f"{_BEARER_PREFIX}{value}"
    else:
        header_value = value
    return AuthCredential(header_name=name, header_value=header_value)
