# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Solomon Nii Amu Darku
"""
Tests for the accuracy gate's scoring.

The gate is only worth having if it actually fails when it should, so these drive the
scorer directly with synthetic findings rather than over the network.
"""

from __future__ import annotations

from pathlib import Path

from provx_sdk.findings import Evidence, FindingDraft, Module, Severity

from lab.harness import Manifest, group_by_rule, load_manifests, score_target

LAB_ROOT = Path(__file__).resolve().parent.parent


def draft(matched_rule: str, severity: Severity = Severity.LOW) -> FindingDraft:
    return FindingDraft(
        title=matched_rule,
        target="http://lab-target",
        module=Module.WEB,
        severity=severity,
        evidence=Evidence(matched_rule=matched_rule),
    )


def positive_manifest() -> Manifest:
    return Manifest(
        path=Path("expected.yml"),
        target="http://lab-target",
        kind="positive",
        expect=[{"id": "security_headers:x-frame-options", "min_severity": "low"}],
    )


def negative_manifest() -> Manifest:
    return Manifest(
        path=Path("expected.yml"), target="http://lab-clean", kind="negative", expect_none=True
    )


def test_expected_finding_scores_as_a_true_positive() -> None:
    score = score_target(positive_manifest(), [draft("security_headers:x-frame-options")])

    assert score.true_positives == {"security_headers:x-frame-options"}
    assert score.passed


def test_missing_expected_finding_is_a_false_negative() -> None:
    score = score_target(positive_manifest(), [])

    assert score.false_negatives == {"security_headers:x-frame-options"}
    assert not score.passed


def test_unexpected_finding_is_a_false_positive() -> None:
    score = score_target(
        positive_manifest(),
        [draft("security_headers:x-frame-options"), draft("security_headers:made-up")],
    )

    assert score.false_positives == {"security_headers:made-up"}
    assert not score.passed


def test_any_finding_on_a_clean_target_fails_the_gate() -> None:
    score = score_target(negative_manifest(), [draft("security_headers:x-frame-options")])

    assert score.false_positives == {"security_headers:x-frame-options"}
    assert not score.passed


def test_clean_target_with_no_findings_passes() -> None:
    score = score_target(negative_manifest(), [])

    assert score.passed
    assert not score.true_positives


def test_finding_below_the_severity_floor_does_not_count_as_a_hit() -> None:
    score = score_target(
        positive_manifest(), [draft("security_headers:x-frame-options", Severity.INFO)]
    )

    assert not score.passed
    assert not score.true_positives


def test_lab_manifests_on_disk_load_and_cover_both_cases() -> None:
    manifests = load_manifests(LAB_ROOT)
    kinds = {manifest.kind for manifest in manifests}

    assert len(manifests) >= 2
    assert kinds == {"positive", "negative"}
    positive = next(m for m in manifests if m.kind == "positive")
    assert "security_headers:content-security-policy" in positive.expected_ids


# --- KI-001 regression: scoring must not depend on finding order ----------------------
# Before the fix, `found` was a last-wins dict, so the same findings scored FAIL as
# (HIGH, INFO) and PASS as (INFO, HIGH). See docs/KNOWN_ISSUES.md.


def rule_draft(severity: Severity) -> FindingDraft:
    return draft("security_headers:x-frame-options", severity)


def test_scoring_is_independent_of_finding_order() -> None:
    manifest = positive_manifest()
    high_first = score_target(manifest, [rule_draft(Severity.HIGH), rule_draft(Severity.INFO)])
    info_first = score_target(manifest, [rule_draft(Severity.INFO), rule_draft(Severity.HIGH)])

    assert high_first.passed == info_first.passed
    assert high_first.true_positives == info_first.true_positives
    assert high_first.false_positives == info_first.false_positives
    assert high_first.false_negatives == info_first.false_negatives


def test_a_rule_counts_as_found_when_any_instance_meets_the_floor() -> None:
    # A check that fires several times on one target passes if one instance is severe
    # enough; the weaker siblings do not drag it below the floor.
    score = score_target(
        positive_manifest(), [rule_draft(Severity.INFO), rule_draft(Severity.HIGH)]
    )

    assert score.true_positives == {"security_headers:x-frame-options"}
    assert score.passed


def test_a_rule_fails_the_floor_only_when_no_instance_reaches_it() -> None:
    score = score_target(
        positive_manifest(), [rule_draft(Severity.INFO), rule_draft(Severity.INFO)]
    )

    assert not score.passed
    assert not score.true_positives


def test_grouping_keeps_every_instance() -> None:
    grouped = group_by_rule([rule_draft(Severity.HIGH), rule_draft(Severity.INFO)])

    assert len(grouped["security_headers:x-frame-options"]) == 2
