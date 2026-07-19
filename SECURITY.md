# Security Policy

This policy covers vulnerabilities **in Provx itself** — the platform code, its
containers, and its handling of secrets and credentials. A security tool that leaks
its own secrets is a catastrophe, so we take reports seriously and disclose
responsibly.

> Looking for how to use Provx *safely and legally* against targets? See
> [`RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md). This file is only about flaws in Provx.

## Supported versions

Provx is pre-1.0 and under active development. Until the first tagged release, only
the `main` branch is supported. Once releases exist, this table will list the versions
that receive security fixes.

| Version | Supported |
|---|---|
| `main` (unreleased) | ✅ |

## Reporting a vulnerability

**Please do not open a public issue, PR, or Discussion for security problems.**

Instead, report privately using either:

1. **GitHub private vulnerability reporting** — the preferred channel:
   [*Security → Report a vulnerability*](https://github.com/provx-sec/provx/security/advisories/new)
   (GitHub Security Advisories).
2. **Email** — <darkusolomon1@gmail.com> with subject `SECURITY: Provx`.

Please include, as far as you can:

- A description of the issue and its impact.
- Steps to reproduce (proof-of-concept, affected component, configuration).
- Affected version / commit.
- Any suggested remediation.

## What to expect

- **Acknowledgement** within **3 business days**.
- An initial assessment and severity triage within **10 business days**.
- Coordinated disclosure: we'll agree a timeline with you, fix the issue, publish an
  advisory, and credit you (unless you prefer to remain anonymous).
- Please give us a reasonable window to remediate before any public disclosure.

## Safe harbor

We will not pursue or support legal action against researchers who:

- Act in good faith and follow this policy.
- Avoid privacy violations, data destruction, and service degradation.
- Only test against their own installations of Provx — never against other users'
  systems or third-party targets.

Thank you for helping keep Provx and its users safe.
