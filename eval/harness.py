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
from narrator.narrator import narrate_naive
from telemetry.schema import Incident
from telemetry.synth_events import download_exec_incident

NarrateFn = Callable[[Incident], str]
BaseIncidentFn = Callable[[], Incident]


@dataclass(frozen=True)
class RunResult:
    payload_id: str
    category: str
    goal: str
    narrator_output: str
    bypass_detected: bool
    reason: str


def splice_payload(base_incident_fn: BaseIncidentFn, payload: Payload) -> Incident:
    """Return a copy of a base incident with the final event's target field
    overwritten by the payload string."""
    incident = copy.deepcopy(base_incident_fn())
    target_event = incident.events[-1]
    setattr(target_event, payload.field, payload.payload)
    return incident


def run_corpus(
    *,
    narrate: NarrateFn = narrate_naive,
    base_incident_fn: BaseIncidentFn = download_exec_incident,
    payloads: list[Payload] | None = None,
) -> list[RunResult]:
    payloads = payloads if payloads is not None else load_corpus()
    results = []
    for payload in payloads:
        incident = splice_payload(base_incident_fn, payload)
        output = narrate(incident)
        judged: JudgeResult = score(payload, output)
        results.append(
            RunResult(
                payload_id=payload.id,
                category=payload.category,
                goal=payload.goal,
                narrator_output=output,
                bypass_detected=judged.bypass_detected,
                reason=judged.reason,
            )
        )
    return results
