"""Input handling for the hardened and structurally-grounded narrator modes:
typed, delimited rendering of attacker-controlled telemetry fields, so the
model has a structural signal that this content is data, not instructions.

Contrast with Event.as_line() (telemetry/schema.py), which is the naive,
unescaped, undelimited serialization the vulnerable baseline uses.
"""
from __future__ import annotations

from telemetry.schema import Event, Incident


def _escape(value: str) -> str:
    """Neutralize characters that could be used to forge a fake closing tag
    and smuggle content past the delimiter boundary."""
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_event_typed(event: Event) -> str:
    """Render one event with every attacker-controlled field explicitly
    typed and delimited (e.g. <proc_image>...</proc_image>), escaped against
    delimiter breakout. Untyped, unescaped concatenation is exactly what lets
    a payload be read as an instruction instead of as data."""
    lines = [f'<event id="{event.id}" ts="{event.ts}" type="{event.type.value}" host="{event.host_id}">']
    if event.proc_image:
        lines.append(f"  <proc_image>{_escape(event.proc_image)}</proc_image>")
    if event.proc_cmdline:
        lines.append(f"  <proc_cmdline>{_escape(event.proc_cmdline)}</proc_cmdline>")
    if event.file_path:
        lines.append(f"  <file_path>{_escape(event.file_path)}</file_path>")
    if event.dns_name:
        lines.append(f"  <dns_name>{_escape(event.dns_name)}</dns_name>")
    if event.remote_addr:
        lines.append(f"  <remote_addr>{_escape(event.remote_addr)}:{event.remote_port}</remote_addr>")
    lines.append("</event>")
    return "\n".join(lines)


def render_incident_typed(incident: Incident) -> str:
    return "\n".join(render_event_typed(e) for e in incident.events)
