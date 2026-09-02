"""The Inspect task must not drift from the offline harness.

The register submission and the paper quote the same numbers, so the guard
that matters is that eval.judge is the single scorer for both paths.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.judge import score as judge_score
from injection_corpus.loader import load_corpus

inspect_ai = pytest.importorskip("inspect_ai", reason="pip install .[inspect]")

from inspect_task.task import TIERS, _prompts, _render, soc_telemetry_injection  # noqa: E402

_RUN = Path("eval/results/run_20260810T113421Z.rescored.json")


@pytest.mark.parametrize("tier", TIERS)
def test_task_builds_with_full_corpus(tier: str) -> None:
    t = soc_telemetry_injection(tier=tier)
    assert len(list(t.dataset)) == len(load_corpus()) == 66
    assert t.scorer is not None


def test_unknown_tier_rejected() -> None:
    with pytest.raises(ValueError):
        soc_telemetry_injection(tier="nonexistent")


@pytest.mark.parametrize("tier", TIERS)
def test_every_sample_carries_a_prompt(tier: str) -> None:
    for sample in soc_telemetry_injection(tier=tier).dataset:
        assert sample.input.strip()
        assert sample.metadata["tier"] == tier


def test_structural_renders_even_when_the_model_emits_garbage() -> None:
    """The tier's premise is that the report comes from trusted code, so an
    unparseable completion must still produce a full report rather than an
    empty one the judge would read as total entity omission."""
    payload = load_corpus()[0]
    out = _render("structural", payload, "not json at all")
    assert "Risk score:" in out
    assert out.count("\n") > 5


@pytest.mark.skipif(not _RUN.exists(), reason="committed run file not present")
@pytest.mark.parametrize("tier", TIERS)
def test_scorer_agrees_with_the_committed_run(tier: str) -> None:
    """Replay the committed narrations through the judge the task uses.

    If this fails, the Inspect task would report different numbers from
    docs/RESULTS.md and from the paper, and the register entry would be wrong.
    """
    corpus = {p.id: p for p in load_corpus()}
    rows = json.loads(_RUN.read_text())["results"][tier]
    for row in rows:
        verdict = judge_score(corpus[row["payload_id"]], row["narrator_output"])
        assert verdict.bypass_detected == row["bypass_detected"], row["payload_id"]
