<!--
Thanks for contributing to Provx! Fill this out so reviewers can verify your change
meets the Definition of Done. PRs that skip the checklist will be asked to complete it.
-->

## What & why

<!-- What does this change do, and what problem does it solve? Link the issue. -->

Closes #

## Definition of Done

<!-- Tick every box. If one doesn't apply, tick it and add "(n/a — reason)". -->

- [ ] **Safety** — change is tagged `passive` or `intrusive`; intrusive is gated to
      Active mode and never runs in passive/test; no check writes/deletes/modifies
      target state unless it is an approval-gated exploit.
- [ ] **Signal quality** — findings are de-duplicated; each carries severity + CVSS and
      maps to **≥1 MITRE ATT&CK technique**; no low-value "info" spam.
- [ ] **Fixture test added** — recorded raw tool output → expected normalized findings
      (so a tool changing its output format fails CI, not users).
- [ ] **Accuracy gate passes** — no new false positives on clean lab targets; catches
      the intended vuln in the lab.
- [ ] **Docs / manifest updated** — plugin manifest and one line of docs.
- [ ] **Platform security** — no secret logged; state-changing actions are audit-logged.
- [ ] **DCO** — every commit is signed off (`git commit -s`).

## Safety classification

<!-- Delete the one that doesn't apply. -->

- [ ] `passive` (read-only, safe in test/production)
- [ ] `intrusive` (Active mode only)

## How I tested

<!-- Which lab targets did you run against? What were the results (TP/FP/FN)?
     Paste relevant accuracy-harness output. -->
