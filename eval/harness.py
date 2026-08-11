"""Runs the injection corpus against a narrator and scores every result.

Each payload is spliced into the field of the final event in a base
incident (per the corpus's category -> field mapping enforced by
injection_corpus.loader), the narrator summarizes the resulting incident,
and eval.judge scores whether the payload's goal was achieved. `narrate` is
injectable so this can run against naive/hardened/structurally-grounded
modes - and be unit tested without hitting the API.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Callable

from eval.judge import JudgeResult, score
from injection_corpus.loader import Payload, load_corpus
from narrator.narrator import narrate_hardened, narrate_naive
from narrator.structural import narrate_structural
from telemetry.schema import Incident
from telemetry.synth_events import beacon_persistence_incident, download_exec_incident

NarrateFn = Callable[[Incident], str]
BaseIncidentFn = Callable[[], Incident]

# Some payload categories only make sense against telemetry that actually
# carries that field type - a registry_key payload spliced into a Linux
# download-and-exec chain would be describing an event that could not exist.
_CATEGORY_BASE_INCIDENT: dict[str, BaseIncidentFn] = {
    "registry_artifact": beacon_persistence_incident,
    "http_artifact": beacon_persistence_incident,
}

# The three tiers compared in RESULTS.md's before/after table.
TIERS: dict[str, NarrateFn] = {
    "naive": narrate_naive,
    "hardened": narrate_hardened,
    "structural": narrate_structural,
}


@dataclass(frozen=True)
class RunResult:
    payload_id: str
    category: str
    goal: str
    narrator_output: str
    bypass_detected: bool
    reason: str


def resolve_base_incident(payload: Payload, default: BaseIncidentFn) -> BaseIncidentFn:
    """Pick a base incident that can actually carry this payload's field."""
    return _CATEGORY_BASE_INCIDENT.get(payload.category, default)


def splice_payload(base_incident_fn: BaseIncidentFn, payload: Payload) -> Incident:
    """Return a copy of a base incident with the payload spliced into the
    target field of the last event that already populates that field.

    Targeting an event that already has the field keeps the resulting
    telemetry coherent - a registry_key payload lands on a registry_set
    event, not on a DNS query. Falls back to the final event when no event
    carries the field, so a mismatched pairing still produces a runnable
    (if less realistic) case rather than silently dropping the payload.
    """
    incident = copy.deepcopy(base_incident_fn())
    candidates = [e for e in incident.events if getattr(e, payload.field, "")]
    target_event = candidates[-1] if candidates else incident.events[-1]
    setattr(target_event, payload.field, payload.payload)
    return incident


def run_corpus(
    *,
    narrate: NarrateFn = narrate_naive,
    base_incident_fn: BaseIncidentFn = download_exec_incident,
    payloads: list[Payload] | None = None,
    on_progress: Callable[[int, int, Payload], None] | None = None,
    on_result: Callable[[RunResult], None] | None = None,
    on_error: Callable[[Payload, Exception], None] | None = None,
    prior: dict[str, RunResult] | None = None,
) -> list[RunResult]:
    """`prior` supplies already-scored results by payload id, so an
    interrupted run resumes instead of re-paying for calls it already made.

    A payload whose narration cannot be obtained is *excluded* rather than
    scored. An unusable response is missing data - it is neither a bypass nor
    a non-bypass, and forcing it into either bucket would bias the rate. The
    caller is told via `on_error` so the exclusion can be reported alongside
    the numbers instead of quietly shrinking the denominator.
    """
    payloads = payloads if payloads is not None else load_corpus()
    prior = prior or {}
    results = []
    for index, payload in enumerate(payloads, start=1):
        if payload.id in prior:
            results.append(prior[payload.id])
            continue
        if on_progress:
            on_progress(index, len(payloads), payload)
        incident = splice_payload(resolve_base_incident(payload, base_incident_fn), payload)
        try:
            output = narrate(incident)
        except Exception as exc:  # noqa: BLE001 - any narrator failure is missing data
            if on_error is None:
                raise
            on_error(payload, exc)
            continue
        judged: JudgeResult = score(payload, output)
        result = RunResult(
            payload_id=payload.id,
            category=payload.category,
            goal=payload.goal,
            narrator_output=output,
            bypass_detected=judged.bypass_detected,
            reason=judged.reason,
        )
        results.append(result)
        if on_result:
            on_result(result)
    return results


def run_all_tiers(
    *,
    base_incident_fn: BaseIncidentFn = download_exec_incident,
    payloads: list[Payload] | None = None,
    on_progress: Callable[[str, int, int, Payload], None] | None = None,
    on_result: Callable[[str, RunResult], None] | None = None,
    on_error: Callable[[str, Payload, Exception], None] | None = None,
    prior: dict[str, dict[str, RunResult]] | None = None,
) -> dict[str, list[RunResult]]:
    """Run the full corpus through every tier in TIERS - the before/after
    comparison RESULTS.md is built from."""
    payloads = payloads if payloads is not None else load_corpus()
    prior = prior or {}
    return {
        name: run_corpus(
            narrate=fn,
            base_incident_fn=base_incident_fn,
            payloads=payloads,
            on_progress=(
                (lambda i, total, p, _tier=name: on_progress(_tier, i, total, p))
                if on_progress
                else None
            ),
            on_result=(
                (lambda r, _tier=name: on_result(_tier, r)) if on_result else None
            ),
            on_error=(
                (lambda p, e, _tier=name: on_error(_tier, p, e)) if on_error else None
            ),
            prior=prior.get(name),
        )
        for name, fn in TIERS.items()
    }


def summarize(results: list[RunResult]) -> dict[str, float]:
    """Bypass rate overall and broken out per goal - the numbers the
    before/after table's cells are built from."""
    if not results:
        return {}
    by_goal: dict[str, list[RunResult]] = {}
    for r in results:
        by_goal.setdefault(r.goal, []).append(r)
    summary = {"overall": sum(r.bypass_detected for r in results) / len(results)}
    for goal, rs in by_goal.items():
        summary[goal] = sum(r.bypass_detected for r in rs) / len(rs)
    return summary
