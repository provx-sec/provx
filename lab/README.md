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

> **Status: Phase 1 placeholder.** No targets are wired in yet. The layout below is the
> plan; targets and the harness land in Phase 2, before the first real check.

## Planned layout

```
lab/
├── positive/     # intentionally-vulnerable targets (should produce findings)
│   ├── juice-shop/       expected.yml + compose
│   ├── dvwa/             expected.yml + compose
│   └── vampi/            expected.yml + compose   (API)
├── clean/        # known-clean baselines (should produce ZERO findings)
│   └── static-site/      expected.yml + compose
└── expected.yml  # or one per target: exactly what should / should not be found
```

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
