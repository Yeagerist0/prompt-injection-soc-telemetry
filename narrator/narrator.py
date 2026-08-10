"""Calls the Claude API to turn an Incident's telemetry into a human-readable
summary.

Naive mode is the vulnerable baseline: Incident.raw_log() (unescaped,
attacker-controlled fields included) is concatenated directly into the
prompt and sent as-is. Hardened mode delimits and types every attacker-
controlled field and forces JSON-only output. Structurally-grounded mode
(narrator/structural.py) goes further still - see that module's docstring.
"""
from __future__ import annotations

import json
import os
from typing import Any

from narrator.backends import get_client
from narrator.prompts.legacy_naive_prompt import build_naive_prompt
from narrator.prompts.system_prompt import HARDENED_RESPONSE_SCHEMA, SYSTEM_PROMPT, build_hardened_prompt
from telemetry.schema import Incident

DEFAULT_MODEL = os.environ.get("NARRATOR_MODEL", "claude-opus-4-8")


def narrate_naive(
    incident: Incident,
    *,
    client: Any | None = None,
    model: str = DEFAULT_MODEL,
) -> str:
    """Summarize an incident using the naive (unhardened) prompt path."""
    client = client or get_client()
    response = client.messages.create(
        model=model,
        max_tokens=1024,
        messages=[{"role": "user", "content": build_naive_prompt(incident)}],
    )
    return "".join(block.text for block in response.content if block.type == "text")


def flatten_hardened_response(parsed: dict) -> str:
    """Render the hardened tier's structured JSON response into the same
    flat, human-readable text shape the other tiers produce, so eval.judge
    can score all tiers with the same checks."""
    severity = parsed.get("severity", "unknown")
    entities = parsed.get("entities", [])
    summary = parsed.get("summary", "")
    return "\n".join(
        [
            f"Severity: {severity}",
            f"Entities: {', '.join(entities) if entities else 'none'}",
            f"Summary: {summary}",
        ]
    )


def narrate_hardened(
    incident: Incident,
    *,
    client: Any | None = None,
    model: str = DEFAULT_MODEL,
) -> str:
    """Summarize an incident using the hardened (delimited, typed, JSON-only)
    prompt path."""
    client = client or get_client()
    response = client.messages.create(
        model=model,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        output_config={"format": {"type": "json_schema", "schema": HARDENED_RESPONSE_SCHEMA}},
        messages=[{"role": "user", "content": build_hardened_prompt(incident)}],
    )
    text = "".join(block.text for block in response.content if block.type == "text")
    return flatten_hardened_response(json.loads(text))
