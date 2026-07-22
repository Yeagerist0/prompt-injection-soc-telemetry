"""Calls the Claude API to turn an Incident's telemetry into a human-readable
summary.

Naive mode is the vulnerable baseline: Incident.raw_log() (unescaped,
attacker-controlled fields included) is concatenated directly into the
prompt and sent as-is. Hardened and structurally-grounded modes are added in
week 3 alongside the eval harness that compares all three.
"""
from __future__ import annotations

import os

import anthropic

from narrator.prompts.legacy_naive_prompt import build_naive_prompt
from telemetry.schema import Incident

DEFAULT_MODEL = os.environ.get("NARRATOR_MODEL", "claude-opus-4-8")


def narrate_naive(
    incident: Incident,
    *,
    client: anthropic.Anthropic | None = None,
    model: str = DEFAULT_MODEL,
) -> str:
    """Summarize an incident using the naive (unhardened) prompt path."""
    client = client or anthropic.Anthropic()
    response = client.messages.create(
        model=model,
        max_tokens=1024,
        messages=[{"role": "user", "content": build_naive_prompt(incident)}],
    )
    return "".join(block.text for block in response.content if block.type == "text")
