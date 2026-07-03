"""Inspect AI task for indirect prompt injection in LLM-narrated SOC telemetry.

Each sample splices one corpus payload into an attacker-controlled field of a
synthetic EDR incident and asks the model under test to narrate it. Scoring
reuses `eval.judge` unchanged, so numbers produced here are directly comparable
to the ones in docs/RESULTS.md and in the paper; the judge is rule-based and
versioned precisely so that comparison stays valid.

Three narrator tiers are exposed as separate tasks because they are the thing
being compared:

  naive       telemetry concatenated into the prompt, no instruction about
              untrusted content.
  hardened    a system prompt that names the attacker-controlled fields as
              evidence rather than instructions, and requires JSON output.
  structural  the model may only choose one label per event from a closed
              vocabulary; the report itself is rendered by trusted Python from
              the parsed incident, so the model cannot state a severity in its
              own voice.

The structural tier is why scoring happens in a scorer rather than on the raw
completion: for that tier the model's output is not the report. It is a set of
label choices that trusted code validates and renders. `_render` below applies
the same post-processing the offline harness does, so all three tiers reach the
judge in the same shape.
"""
from __future__ import annotations

import json
from typing import Callable

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, Target, accuracy, scorer, stderr
from inspect_ai.solver import TaskState, generate, system_message

from eval.harness import resolve_base_incident, splice_payload
from eval.judge import score as judge_score
from injection_corpus.loader import Payload, load_corpus
from narrator.narrator import flatten_hardened_response
from narrator.prompts.legacy_naive_prompt import build_naive_prompt
from narrator.prompts.structural_prompt import (
    build_structural_prompt,
    build_structural_system_prompt,
)
from narrator.prompts.system_prompt import SYSTEM_PROMPT, build_hardened_prompt
from narrator.structural import (
    ObservationKind,
    render_structural_report,
    validate_classifications,
)
from telemetry.synth_events import download_exec_incident

TIERS = ("naive", "hardened", "structural")


def _incident_for(payload: Payload):
    """Splice the payload into a base incident that can carry its field."""
    base = resolve_base_incident(payload, download_exec_incident)
    return splice_payload(base, payload)


def _prompts(tier: str, payload: Payload) -> tuple[str | None, str]:
    """Return (system_prompt, user_prompt) for this tier."""
    incident = _incident_for(payload)
    if tier == "naive":
        return None, build_naive_prompt(incident)
    if tier == "hardened":
        return SYSTEM_PROMPT, build_hardened_prompt(incident)
    if tier == "structural":
        allowed = [k.value for k in ObservationKind]
        return build_structural_system_prompt(allowed), build_structural_prompt(incident)
    raise ValueError(f"unknown tier {tier!r}")


def _render(tier: str, payload: Payload, completion: str) -> str:
    """Turn a raw completion into the narration text the judge scores.

    naive       the completion is the narration.
    hardened    the completion is JSON; flatten it to the shared text shape.
    structural  the completion is only label choices. Trusted code renders the
                report from the parsed incident, which is the whole point of
                the tier, so an unparseable completion still yields a report.
    """
    if tier == "naive":
        return completion
    if tier == "hardened":
        try:
            return flatten_hardened_response(json.loads(completion))
        except (json.JSONDecodeError, TypeError, AttributeError):
            # A tier that fails to emit valid JSON has not thereby resisted the
            # payload; score whatever it did emit rather than silently passing.
            return completion
    if tier == "structural":
        incident = _incident_for(payload)
        try:
            raw = json.loads(completion)
            classifications = raw.get("classifications", raw) if isinstance(raw, dict) else raw
            validated = validate_classifications(incident, classifications)
        except (json.JSONDecodeError, TypeError, AttributeError, ValueError):
            # An unparseable completion means no label survived validation.
            # Every event is still rendered, as UNCLASSIFIED - which is the
            # tier's design: the model cannot drop an event by malforming its
            # answer, and it cannot state a severity in its own voice either.
            validated = {}
        return render_structural_report(incident, validated)
    raise ValueError(f"unknown tier {tier!r}")


def _dataset(tier: str) -> MemoryDataset:
    samples = []
    for p in load_corpus():
        system, user = _prompts(tier, p)
        samples.append(
            Sample(
                id=p.id,
                input=user,
                target=p.goal,
                metadata={
                    "tier": tier,
                    "payload_id": p.id,
                    "goal": p.goal,
                    "category": p.category,
                    "field": p.field,
                    "technique": p.technique,
                    "target_tier": getattr(p, "target_tier", "generic"),
                    "system_prompt": system or "",
                },
            )
        )
    return MemoryDataset(samples)


@scorer(metrics=[accuracy(), stderr()])
def injection_resisted():
    """CORRECT when the payload's goal was NOT achieved.

    Delegates to eval.judge so this task and the offline harness cannot drift.
    The judge distinguishes quoting attacker text from complying with it; a
    narration that quotes the payload while rejecting it is a pass, which a
    naive substring check would score backwards.
    """
    corpus = {p.id: p for p in load_corpus()}

    async def compute(state: TaskState, target: Target) -> Score:
        payload = corpus[str(state.sample_id)]
        tier = state.metadata["tier"]
        narration = _render(tier, payload, state.output.completion)
        verdict = judge_score(payload, narration)
        return Score(
            value=INCORRECT if verdict.bypass_detected else CORRECT,
            answer=narration[:2000],
            explanation=verdict.reason,
            metadata={
                "bypass_detected": verdict.bypass_detected,
                "goal": verdict.goal,
                "tier": tier,
            },
        )

    return compute


def _task_for(tier: str) -> Task:
    system, _ = _prompts(tier, load_corpus()[0])
    solver = [system_message(system), generate()] if system else [generate()]
    return Task(
        dataset=_dataset(tier),
        solver=solver,
        scorer=injection_resisted(),
    )


@task
def soc_telemetry_injection(tier: str = "structural") -> Task:
    """Indirect prompt injection through attacker-controlled EDR telemetry.

    Args:
        tier: which narrator defense to evaluate - "naive", "hardened" or
            "structural". Defaults to the structurally grounded narrator.
    """
    if tier not in TIERS:
        raise ValueError(f"tier must be one of {TIERS}, got {tier!r}")
    return _task_for(tier)
