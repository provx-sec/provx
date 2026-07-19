# lab/ — accuracy benchmark & practice targets

This directory is the **accuracy baseline** for Provx (Phase 2 of the Master Checklist).
It holds deliberately-vulnerable targets (**positive** cases) and known-clean targets
(**negative** cases). The accuracy harness runs Provx's checks against these and scores
**True Positives / False Positives / False Negatives** vs an `expected.yml` manifest per
target — failing any PR that adds a false positive on a clean target or misses a known
vuln.

See [`../docs/VALIDATION_and_REFERENCE_SYSTEMS.md`](../docs/VALIDATION_and_REFERENCE_SYSTEMS.md)
and [`../docs/START_HERE_Master_Checklist.md`](../docs/START_HERE_Master_Checklist.md)
(Phase 2) for the full design.

> **Status: live for the `security_headers` check.** Two nginx targets are wired in and the
> harness is a real CI gate. More targets land alongside the checks that need them.

Run it with `make accuracy` (brings the targets up, scores, tears them down). The gate
exits non-zero on any false positive or false negative.

## Layout

```text
lab/
├── positive/                    # intentionally-vulnerable targets (should produce findings)
│   └── missing-headers/         nginx sending no security headers + expected.yml   [live]
├── clean/                       # known-clean baselines (should produce ZERO findings)
│   └── hardened/                nginx sending all of them + expected.yml           [live]
├── harness.py                   # scores TP/FP/FN, exits non-zero on FP or FN
├── tests/                       # tests for the scorer itself
└── expected.yml                 # index + schema; the real oracles are per-target
```

Planned additions as the matching checks arrive: OWASP Juice Shop, DVWA (web), VAmPI (API).

Targets run under the compose `lab` profile on an `internal: true` network with no
published ports, so `docker compose up` never starts them and nothing is reachable from
outside the host.

## Positive cases (candidates)

- **OWASP Juice Shop**, **WebGoat** — web
- **DVWA**, **bWAPP** — classic web
- **VAmPI**, **crAPI** — APIs

## Negative cases

- Minimal clean static sites / hardened services that must yield no findings — the
  false-positive tripwire.

## Oracles (accuracy measuring sticks)

- **OWASP Benchmark** — objective TP/FP scorecard tracked release over release.
- **Differential testing** vs OWASP ZAP, Nuclei (official), OpenVAS/Greenbone, Nikto on
  the same targets — where Provx disagrees with consensus, investigate the FP/FN.

## Safety

Every target here is isolated on an internal Docker network. These are for authorized,
self-contained testing only — see [`../RESPONSIBLE_USE.md`](../RESPONSIBLE_USE.md).
