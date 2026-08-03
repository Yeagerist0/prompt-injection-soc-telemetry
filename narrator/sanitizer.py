"""Input handling for the hardened and structurally-grounded narrator modes:
typed, delimited rendering of attacker-controlled telemetry fields, so the
model has a structural signal that this content is data, not instructions.

Contrast with Event.as_line() (telemetry/schema.py), which is the naive,
unescaped, undelimited serialization the vulnerable baseline uses.

Security note: the whole value of this module is that the <event> envelope
is NOT forgeable from inside a field. That means every interpolated value -
including the ones in the opening tag's attributes - has to be escaped, not
just the ones in text content. `host_id` in particular is frequently
self-reported by the monitored host in real EDR deployments, so treating it
as trusted just because the agent stamped it would be wrong.
"""
from __future__ import annotations

from telemetry.schema import Event, Incident

# Order matters: & must be replaced first or it double-escapes the others.
_ENTITIES = (
    ("&", "&amp;"),
    ("<", "&lt;"),
    (">", "&gt;"),
    ('"', "&quot;"),
    ("'", "&#39;"),
)

# Fields carrying attacker-controlled content, rendered as child tags.
_TAGGED_FIELDS = (
    "proc_image",
    "proc_cmdline",
    "file_path",
    "dns_name",
    "registry_key",
    "user_agent",
)


def _escape(value: str) -> str:
    """Full XML entity escaping, including both quote characters.

    Quotes matter even for values that currently land in text content: a
    field that gets moved into an attribute later must not silently become
    a breakout, and the escaping cost is nil.
    """
    for char, entity in _ENTITIES:
        value = value.replace(char, entity)
    return value


def _attr(name: str, value: object) -> str:
    """Render one escaped name="value" attribute pair."""
    return f'{name}="{_escape(str(value))}"'


def render_event_typed(event: Event) -> str:
    """Render one event with every attacker-controlled field explicitly
    typed and delimited (e.g. <proc_image>...</proc_image>), escaped against
    delimiter breakout in both attribute and text position. Untyped,
    unescaped concatenation is exactly what lets a payload be read as an
    instruction instead of as data."""
    attrs = " ".join(
        [
            _attr("id", event.id),
            _attr("ts", event.ts),
            _attr("type", event.type.value),
            _attr("host", event.host_id),
        ]
    )
    lines = [f"<event {attrs}>"]
    for field in _TAGGED_FIELDS:
        value = getattr(event, field, "")
        if value:
            lines.append(f"  <{field}>{_escape(str(value))}</{field}>")
    if event.remote_addr:
        lines.append(
            f"  <remote_addr>{_escape(event.remote_addr)}:{_escape(str(event.remote_port))}</remote_addr>"
        )
    lines.append("</event>")
    return "\n".join(lines)


def render_incident_typed(incident: Incident) -> str:
    return "\n".join(render_event_typed(e) for e in incident.events)
