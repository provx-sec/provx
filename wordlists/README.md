# wordlists/ — discovery & fuzzing wordlists

Wordlists used by content-discovery, fuzzing, and enumeration adapters (feroxbuster,
ffuf, subdomain enumeration, etc.).

> **Status: Phase 1 placeholder.** No wordlists are bundled yet.

## Licensing note

Wordlists carry their own licenses. **Do not commit wordlists whose license is
incompatible with redistribution.** Prefer one of:

- Referencing well-known upstream lists (e.g. SecLists) and fetching them at build/run
  time, rather than vendoring them here, or
- Committing only small, purpose-built lists authored for Provx under
  [Apache-2.0](../LICENSE).

Record the source and license of every list added here. When in doubt, fetch instead of
vendor.
