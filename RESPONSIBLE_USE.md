# Responsible Use

Provx is **offensive security tooling**. Used correctly it helps you find and fix real
vulnerabilities in systems you own or are authorized to test. Used incorrectly it is a
weapon and, in most jurisdictions, a crime. This document is the line.

By using, contributing to, or distributing Provx, you agree to the following. This is
in addition to the warranty disclaimer in the [Apache-2.0 LICENSE](LICENSE) — Provx is
provided "AS IS", with no guarantee of fitness or completeness.

## 1. Authorized use only

You may run Provx only against systems that you own, or for which you have **explicit,
written authorization** to test, within the agreed scope and rules of engagement.
Scanning, probing, or exploiting systems without permission is illegal and unethical.
You are solely responsible for ensuring you have authorization before every engagement.

## 2. Safe by default — and keep it that way

Provx is designed to be non-destructive by default. Do not contribute or configure
features that undermine this:

- **Passive/test mode is read-only.** No check may create, modify, or delete data on a
  target in passive mode. If a check cannot guarantee that, it must be tagged
  `intrusive`.
- **Intrusive checks require Active mode** plus recorded authorization and rules of
  engagement. They are gated and logged.
- **Exploitation requires per-finding human approval**, runs sandboxed, and produces
  non-destructive proof only, with a full replay trail.
- **Scope is enforced before every action** — allow/deny is checked at the adapter
  boundary, not trusted from upstream.

See the full **Safety Contract** in [`docs/ROADMAP.md`](docs/ROADMAP.md) §8.

## 3. We advise test environments

Provx is designed to be safe to point at production because it is non-destructive — but
a test/staging environment is always the recommended default. Production testing should
only ever happen with explicit authorization and agreed rules of engagement.

## 4. Prohibited contributions

We will not accept features whose only sensible purpose is unauthorized attack — for
example, built-in target-less mass exploitation, or anything designed primarily to
evade detection for malicious ends. Provx interoperates with the security ecosystem; it
is not a botnet toolkit.

## 5. Data, secrets, and privacy

- Do not use Provx to collect, exfiltrate, or retain data you are not authorized to
  access.
- Provx protects its own secrets (encrypted credentials/tokens/sessions, RBAC, audit
  log). Do not disable these protections or log secrets.

## 6. Your responsibility

Neither the authors nor contributors of Provx are responsible for misuse or for any
damage caused by running it. The real protection here is the safety design, the
human-in-the-loop validation, and honest labeling — not a line of legal text. Use Provx
the way it was built to be used: **authorized, safe, and honest.**

If you are unsure whether a use is authorized, assume it is not, and do not proceed.
