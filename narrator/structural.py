"""Tier 3: structurally-grounded narration.

The model's only degree of freedom is choosing, for every event, one label
from a fixed allow-list (ObservationKind). Everything else in the final
report - the risk score, the technique set, and the literal fields of every
event - comes from trusted Incident/Event data and is rendered by fixed
Python string templates, never by LLM-authored free text.

The model's chosen label is validated against the allow-list and the
incident's real event ids before it's trusted: an invented label, a missing
event id, a duplicate, or an id that doesn't belong to this incident all
fall back to ObservationKind.UNCLASSIFIED rather than being accepted. Every
event is rendered regardless of what the model says, so an event can't be
silently dropped from the report the way it could be in the naive or
hardened tiers.

This mirrors the statement-kind + event-ID citation guard in
backend/narrate/narrate.go from the main SentinelX project: the LLM selects
from a closed vocabulary, trusted code renders the actual text.
"""
from __future__ import annotations

import json
from enum import Enum
from typing import Any

from narrator.backends import get_client
from narrator.narrator import DEFAULT_MODEL
from narrator.prompts.structural_prompt import build_structural_prompt, build_structural_system_prompt
from telemetry.schema import Event, EventType, Incident


class ObservationKind(str, Enum):
    MALICIOUS_ACTIVITY = "malicious_activity"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    NETWORK_COMMUNICATION = "network_communication"
    FILE_ACTIVITY = "file_activity"
    ROUTINE_ADMINISTRATION = "routine_administration"
    UNCLASSIFIED = "unclassified"


_CLASSIFICATION_SCHEMA = {
    "type": "object",
    "properties": {
        "classifications": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "event_id": {"type": "string"},
                    "kind": {"type": "string", "enum": [k.value for k in ObservationKind]},
                },
                "required": ["event_id", "kind"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["classifications"],
    "additionalProperties": False,
}

_TEMPLATES: dict[EventType, str] = {
    EventType.PROCESS_START: "[{ts}] process started on {host_id}: {proc_image}{cmdline_suffix}",
    EventType.FILE_WRITE: "[{ts}] file written on {host_id}: {file_path}",
    EventType.FILE_READ: "[{ts}] file read on {host_id}: {file_path}",
    EventType.NET_CONNECT: "[{ts}] network connection from {host_id} to {remote_addr}:{remote_port}",
    EventType.DNS_QUERY: "[{ts}] DNS query from {host_id}: {dns_name}",
    EventType.REGISTRY_SET: "[{ts}] registry value set on {host_id}: {registry_key}",
    EventType.HTTP_REQUEST: "[{ts}] HTTP request from {host_id} to {remote_addr}:{remote_port} (user-agent: {user_agent})",
}


def render_event_line(event: Event, kind: ObservationKind) -> str:
    """Render one event's line using a fixed, per-event-type template. The
    model never authors this text - it only chose `kind`."""
    cmdline_suffix = f' (cmdline: "{event.proc_cmdline}")' if event.proc_cmdline else ""
    line = _TEMPLATES[event.type].format(
        ts=event.ts,
        host_id=event.host_id,
        proc_image=event.proc_image,
        cmdline_suffix=cmdline_suffix,
        file_path=event.file_path,
        remote_addr=event.remote_addr,
        remote_port=event.remote_port,
        dns_name=event.dns_name,
        registry_key=event.registry_key,
        user_agent=event.user_agent,
    )
    return f"- [{kind.value}] {line}"


def validate_classifications(incident: Incident, raw_classifications: list[dict]) -> dict[str, ObservationKind]:
    """Turn the model's raw classification list into a trusted event_id ->
    ObservationKind mapping. Anything not traceable to a real event id in
    this incident, or not one of the allow-listed kind values, is dropped -
    it never reaches the rendered report. Missing/dropped entries are
    filled with UNCLASSIFIED by the caller, not here.

    Duplicate event_ids are rejected rather than last-write-wins: a response
    that classifies the same event twice is malformed, and silently keeping
    one of the two would let a trailing entry override an earlier one. Both
    are discarded so the event falls through to UNCLASSIFIED, which is the
    safe direction (it stays visible and unendorsed, rather than inheriting
    whichever label happened to come last).
    """
    valid_ids = {e.id for e in incident.events}
    valid_kinds = {k.value for k in ObservationKind}

    seen: set[str] = set()
    duplicated: set[str] = set()
    validated: dict[str, ObservationKind] = {}
    for entry in raw_classifications:
        if not isinstance(entry, dict):
            continue
        event_id = entry.get("event_id")
        kind_str = entry.get("kind")
        if event_id not in valid_ids or kind_str not in valid_kinds:
            continue
        if event_id in seen:
            duplicated.add(event_id)
            continue
        seen.add(event_id)
        validated[event_id] = ObservationKind(kind_str)

    for event_id in duplicated:
        validated.pop(event_id, None)
    return validated


def render_structural_report(incident: Incident, classifications: dict[str, ObservationKind]) -> str:
    """Render the full report: a trusted header (risk score, technique set -
    never asked of the LLM) followed by every event, in order, using its
    validated classification (or UNCLASSIFIED if none survived validation)."""
    lines = [
        f"Incident {incident.id} on host {incident.host_id}",
        f"Risk score: {incident.risk_score}/100",
        f"Techniques observed: {', '.join(incident.technique_set) if incident.technique_set else 'none'}",
        "",
        "Events:",
    ]
    for event in incident.events:
        kind = classifications.get(event.id, ObservationKind.UNCLASSIFIED)
        lines.append(render_event_line(event, kind))
    return "\n".join(lines)


def narrate_structural(
    incident: Incident,
    *,
    client: Any | None = None,
    model: str = DEFAULT_MODEL,
) -> str:
    """Summarize an incident using the structurally-grounded prompt path."""
    client = client or get_client()
    response = client.messages.create(
        model=model,
        max_tokens=1024,
        system=build_structural_system_prompt([k.value for k in ObservationKind]),
        output_config={"format": {"type": "json_schema", "schema": _CLASSIFICATION_SCHEMA}},
        messages=[{"role": "user", "content": build_structural_prompt(incident)}],
    )
    text = "".join(block.text for block in response.content if block.type == "text")
    raw_classifications = json.loads(text).get("classifications", [])
    classifications = validate_classifications(incident, raw_classifications)
    return render_structural_report(incident, classifications)
