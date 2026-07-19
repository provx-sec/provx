# Governance

This document describes how decisions are made in Provx, how the project is structured,
and how that structure changes as the community grows. It is intentionally lightweight
for the current stage and will evolve with the project.

## Project stage

Provx is an early-stage, open-core project. Today it is maintained by a single
maintainer (**Solomon Nii Amu Darku** — "SNAD", [@darkusolomon1](mailto:darkusolomon1@gmail.com)).
The model below is designed so it can grow into a multi-maintainer project without
re-litigating the basics.

## Roles

- **Contributor** — anyone who opens an issue or PR. Contributions are accepted under
  [Apache-2.0](LICENSE) with a [DCO](CONTRIBUTING.md#2-developer-certificate-of-origin-dco--required)
  sign-off.
- **Maintainer** — has merge rights and reviews contributions against the
  [Definition of Done](CONTRIBUTING.md) and the [Safety Contract](docs/ROADMAP.md).
  Maintainers are listed as owners in [`CODEOWNERS`](CODEOWNERS).
- **Area owner** — a maintainer accountable for a specific area (e.g. web module,
  reporting, CI). Encoded per-path in `CODEOWNERS` so the right person must approve
  changes to their area.
- **Lead maintainer / BDFL** — for now, the project founder. Breaks ties and holds
  final say on scope, the roadmap, and the Safety Contract.

## How decisions are made

1. **Lazy consensus** for most changes: a PR that passes CI and gets an approving
   CODEOWNER review can merge. Silence is assent.
2. **Discussion for larger changes** (new modules, architecture shifts, policy changes):
   open a GitHub Discussion or a tracking issue; aim for consensus among maintainers.
3. **The Safety Contract is not up for casual change.** Any change that weakens
   safety-by-default, scope enforcement, or the human-in-the-loop model requires
   explicit lead-maintainer approval and a documented rationale.

## Becoming a maintainer

Contributors who show sustained, high-quality involvement — good PRs that meet the DoD,
helpful reviews, constructive participation — may be invited to become maintainers or
area owners. The lead maintainer extends invitations; as the team grows this will move
to a maintainer vote. New maintainers are added to `CODEOWNERS` in a PR.

## Changing the roadmap

The roadmap lives in [`docs/ROADMAP.md`](docs/ROADMAP.md) and the milestones (`v0.1
MVP`, `v0.5 Depth`, `v1.0 Full`, `v2.0 Reach`). Changes are proposed via issue/PR and
agreed by maintainers; the public board reflects current priorities and where help is
wanted.

## Branch protection & review

`main` is always releasable. Once the project is on GitHub, `main` is protected:
require a PR, passing CI, at least one approving review from a CODEOWNER, DCO sign-off,
linear history, and no direct pushes.

## Code of Conduct

All participation is governed by the [Contributor Covenant](CODE_OF_CONDUCT.md).
Enforcement is a maintainer responsibility.

## Changing this document

Amendments to governance are made by PR and require lead-maintainer approval. As the
project matures, this document will grow to describe a maintainer council and a formal
voting process.
