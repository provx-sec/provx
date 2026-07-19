# Trademark — the "Provx" mark

The name is a canonical decision (see [`00_README_docs_index.md`](00_README_docs_index.md)), so
the risks attached to it belong in the decision record rather than in someone's memory.

This file records what was checked, what was found, what was **accepted rather than resolved**,
and what would force a re-check.

---

## Scope of the check — read this before relying on any of it

**A general web search. Not a clearance search, not a legal opinion, and not written by a lawyer.**

The USPTO's own search (`tmsearch.uspto.gov`) is a JavaScript application with no fetchable API,
and the third-party mirrors (`uspto.report`, `trademarkia.com`) refuse automated requests. So the
authoritative register was never actually queried — only the open web was. A live registration
that no page happens to describe would not appear below.

Treat the findings as *reconnaissance that found nothing disqualifying*, which is a materially
weaker statement than *nothing is there*.

## Findings — 2026-07-19

| Mark | Owner / context | Class | Assessment |
|---|---|---|---|
| **PROVOX** | Atos Medical AB (Sweden) — voice prostheses and laryngectomy care | 10 (medical devices) | Live and near-identical, but the goods are unrelated to security software. Low risk. |
| **PROVOX** | Emerson — distributed control system, introduced 1980, still supported via documented DeltaV migration services | industrial control software | **The one that matters.** Control software is adjacent to class 9 / 42, and PROVX differs from PROVOX by a single vowel. |
| **PROVX** | Provident Trust Strategy Fund — NASDAQ ticker | 36 (financial services) | A ticker is not necessarily a registered mark, and the services are remote from ours. Low risk. |
| **ProvX** | Xidian University, Aug 2025 — counterfactual attack explanations for provenance-based detection ([arXiv:2508.06073](https://arxiv.org/abs/2508.06073)) | n/a | Not a trademark and no commercial use, so it blocks nothing. But it is an exact-name collision *inside security*, which costs us search discoverability and leaves the name available for someone else to commercialize. |
| Provarex · Provox Systems · ProvideX (Sage) | Various | — | Weaker similarity. Recorded for completeness. |

## Decision

**Proceed as Provx.** The PROVOX-in-software adjacency is **accepted, not resolved.**

Reasoning: nothing disqualifying surfaced in security software; the repository is already public
under `provx-sec/provx`, so a rename would now cost more than the residual risk appears to justify;
and no filing is planned in the near term, which is where a likelihood-of-confusion analysis would
actually bite.

The exposure being accepted is that a future USPTO application could draw a refusal citing
Emerson's PROVOX, and that the arXiv ProvX will compete for the name in search results.

## Re-check triggers

Revisit this file — and get an actual clearance search from counsel — before any of:

- filing a trademark application anywhere;
- paid marketing, or a launch that puts the name in front of a broad audience;
- a funding round or acquisition, where diligence will ask;
- an approach from any PROVOX or ProvX rights-holder;
- offering a paid edition under the name.

Anything that turns up **live in class 9 or class 42** reopens the naming decision outright.
