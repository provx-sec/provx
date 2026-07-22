# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Accuracy gate.

Runs Provx's checks against the lab targets and scores True Positives, False Positives, and
False Negatives against each target's ``expected.yml`` oracle. Exits non-zero on any FP or
FN, so a PR that starts crying wolf on the clean target - or stops catching a known issue -
fails CI rather than users.

Findings are matched by ``matched_rule`` (``adapter:check``), which is the stable identity
the manifests are written against.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from provx_sdk.findings import FindingDraft, Severity
from provx_sdk.registry import load_adapter
from provx_sdk.scope import ScopePolicy, target_host

LAB_ROOT = Path(__file__).resolve().parent
SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass
class Manifest:
    """One target's oracle, loaded from its expected.yml."""

    path: Path
    target: str
    kind: str
    expect: list[dict[str, Any]] = field(default_factory=list)
    expect_none: bool = False
    # Lab targets on a local/loopback address need the scope engine's dangerous-range
    # override; compose-networked targets (the default) do not.
    allow_dangerous_ranges: bool = False
    # Which adapter owns this target. One gate run scores one adapter, so a target is only
    # probed by the adapter named here (defaults to the first shipped adapter for manifests
    # written before adapters were mixed).
    adapter: str = "security_headers"

    @property
    def expected_ids(self) -> set[str]:
        return {str(item["id"]) for item in self.expect}

    def min_severity(self, check_id: str) -> Severity | None:
        for item in self.expect:
            if str(item["id"]) == check_id and "min_severity" in item:
                return Severity(str(item["min_severity"]))
        return None


@dataclass
class Score:
    """TP / FP / FN tallies for one target."""

    target: str
    true_positives: set[str] = field(default_factory=set)
    false_positives: set[str] = field(default_factory=set)
    false_negatives: set[str] = field(default_factory=set)

    @property
    def passed(self) -> bool:
        return not self.false_positives and not self.false_negatives


def load_manifests(root: Path) -> list[Manifest]:
    """Load every per-target expected.yml under the lab directory."""
    manifests: list[Manifest] = []
    for path in sorted(root.glob("*/*/expected.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        manifests.append(
            Manifest(
                path=path,
                target=str(data["target"]),
                kind=str(data.get("kind", "positive")),
                expect=list(data.get("expect") or []),
                expect_none=bool(data.get("expect_none", False)),
                allow_dangerous_ranges=bool(data.get("allow_dangerous_ranges", False)),
                adapter=str(data.get("adapter", "security_headers")),
            )
        )
    return manifests


def check_id(draft: FindingDraft) -> str:
    """The stable identity a manifest entry refers to."""
    evidence = draft.evidence
    if evidence is None or not evidence.matched_rule:
        raise ValueError(f"finding {draft.title!r} has no matched_rule to score against")
    return evidence.matched_rule


def group_by_rule(drafts: list[FindingDraft]) -> dict[str, list[FindingDraft]]:
    """Collect findings under their rule id, keeping every instance.

    A check may legitimately fire more than once against one target (per path, per
    parameter). Keeping only one - as a dict comprehension would - made the verdict depend
    on iteration order, which is the one thing a determinism gate cannot do (PX-DETERMINISM).
    """
    grouped: dict[str, list[FindingDraft]] = {}
    for draft in drafts:
        grouped.setdefault(check_id(draft), []).append(draft)
    return grouped


def meets_floor(drafts: list[FindingDraft], floor: Severity | None) -> bool:
    """Whether any instance of a rule reaches the manifest's minimum severity."""
    if floor is None:
        return True
    return any(
        SEVERITY_ORDER.index(draft.severity) >= SEVERITY_ORDER.index(floor) for draft in drafts
    )


def score_target(manifest: Manifest, drafts: list[FindingDraft]) -> Score:
    """Compare one target's findings to its oracle.

    Order-independent by construction: the same set of findings scores identically however
    they are ordered.
    """
    found = group_by_rule(drafts)
    expected = manifest.expected_ids
    result = Score(target=manifest.target)

    for found_id, instances in found.items():
        if found_id not in expected:
            result.false_positives.add(found_id)
            continue
        floor = manifest.min_severity(found_id)
        if floor is not None and not meets_floor(instances, floor):
            result.false_positives.add(f"{found_id} (below {floor.value})")
            continue
        result.true_positives.add(found_id)

    result.false_negatives = expected - set(found)
    return result


def policy_for(manifest: Manifest) -> ScopePolicy:
    """Scope the harness to exactly the one target it is about to score.

    The harness used to call ``probe`` with no scope at all, relying on Docker's internal
    network for containment. Scope is Provx's own control and belongs here too, narrowed to
    a single host so a misconfigured lab target cannot reach anything else.
    """
    return ScopePolicy(
        allow=[target_host(manifest.target)],
        allow_dangerous_ranges=manifest.allow_dangerous_ranges,
    )


async def run(root: Path, adapter_name: str) -> list[Score]:
    """Probe the lab targets this adapter owns and score the results.

    A target is scored only by the adapter named in its manifest: probing a TLS target with
    the header adapter (or vice versa) would report findings the oracle never listed, so the
    run stays scoped to one adapter's targets.
    """
    adapter = load_adapter(adapter_name)
    scores: list[Score] = []
    for manifest in load_manifests(root):
        if manifest.adapter != adapter_name:
            continue
        raw = await adapter.probe(manifest.target, policy=policy_for(manifest))
        scores.append(score_target(manifest, adapter.parse_output(raw)))
    return scores


def report(scores: list[Score]) -> bool:
    """Print the scorecard and report whether the gate passed."""
    if not scores:
        print("accuracy gate: no lab manifests found", file=sys.stderr)
        return False

    print(f"{'TARGET':<34} {'TP':>4} {'FP':>4} {'FN':>4}  RESULT")
    for score in scores:
        verdict = "pass" if score.passed else "FAIL"
        print(
            f"{score.target:<34} {len(score.true_positives):>4} "
            f"{len(score.false_positives):>4} {len(score.false_negatives):>4}  {verdict}"
        )
        for false_positive in sorted(score.false_positives):
            print(f"    false positive: {false_positive}")
        for false_negative in sorted(score.false_negatives):
            print(f"    false negative: {false_negative}")

    return all(score.passed for score in scores)


def main() -> int:
    parser = argparse.ArgumentParser(description="Score Provx against the lab targets.")
    parser.add_argument("--lab-root", type=Path, default=LAB_ROOT)
    parser.add_argument("--adapter", default="security_headers")
    args = parser.parse_args()

    scores = asyncio.run(run(args.lab_root, args.adapter))
    return 0 if report(scores) else 1


if __name__ == "__main__":
    raise SystemExit(main())
