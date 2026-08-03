"""Typed telemetry event schema.

Deliberately mirrors the shape of a real EDR's normalized event (see
SentinelX's Go `correlate.Event` — this project is a standalone research
artifact, not a copy of that codebase, but the schema shape matters: the whole
point is that these are the exact string fields a real EDR narrator would read
verbatim from kernel/agent telemetry. Every field marked ATTACKER-CONTROLLED
below is a value an attacker on the monitored host chooses directly (a process
name, a command line, a file path, a DNS name) — none of it is sanitized or
validated by the collection layer, because it isn't supposed to be: an EDR's
job is to record what happened, not judge it. That's exactly what makes it a
prompt-injection channel the moment an LLM reads it as English text.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EventType(str, Enum):
    PROCESS_START = "process_start"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    NET_CONNECT = "net_connect"
    DNS_QUERY = "dns_query"
    REGISTRY_SET = "registry_set"
    HTTP_REQUEST = "http_request"


@dataclass
class Event:
    """One normalized telemetry record.

    ATTACKER-CONTROLLED fields (never sanitized by the collector, by design):
    proc_image, proc_cmdline, file_path, dns_name, registry_key, user_agent,
    and remote_addr are all strings an attacker on the host chooses.

    ts/type/proc_guid are assigned by the agent/backend. host_id is stamped by
    the agent too, but in most real deployments it originates from the host's
    own self-reported hostname — so narrator/sanitizer.py escapes it like any
    other untrusted value rather than trusting the envelope.
    """

    id: str
    ts: str  # ISO8601, kept as str: this is what actually gets serialized into a prompt
    type: EventType
    host_id: str
    proc_guid: str
    proc_image: str = ""      # ATTACKER-CONTROLLED (process name/path)
    proc_cmdline: str = ""    # ATTACKER-CONTROLLED (full command line)
    parent_guid: str = ""
    file_path: str = ""       # ATTACKER-CONTROLLED (file_write/file_read only)
    remote_addr: str = ""     # host-chosen destination, not usually injection-relevant
    remote_port: int = 0
    dns_name: str = ""        # ATTACKER-CONTROLLED (dns_query only — attacker controls their own C2 domain)
    registry_key: str = ""    # ATTACKER-CONTROLLED (registry_set only — key path and value the attacker writes)
    user_agent: str = ""      # ATTACKER-CONTROLLED (http_request only — fully attacker-chosen request header)

    def as_line(self) -> str:
        """Render one event as the naive narrator would: a plain log line built
        by simple string formatting, with attacker-controlled fields dropped in
        unescaped and unmarked. This is intentionally the naive/vulnerable
        serialization — see narrator/sanitizer.py for the hardened one."""
        parts = [f"[{self.ts}] {self.type.value} host={self.host_id} proc={self.proc_image}"]
        if self.proc_cmdline:
            parts.append(f'cmdline="{self.proc_cmdline}"')
        if self.file_path:
            parts.append(f"path={self.file_path}")
        if self.remote_addr:
            parts.append(f"dst={self.remote_addr}:{self.remote_port}")
        if self.dns_name:
            parts.append(f"query={self.dns_name}")
        if self.registry_key:
            parts.append(f"key={self.registry_key}")
        if self.user_agent:
            parts.append(f'ua="{self.user_agent}"')
        return " ".join(parts)


@dataclass
class Incident:
    """A correlated group of events an analyst (or LLM narrator) would review
    together — the same shape as a SentinelX Investigation: several raw events,
    a computed risk score, and MITRE technique tags. The risk_score and
    technique_set are TRUSTED — in a real EDR they come from the deterministic
    correlation engine, never from the LLM. The narrator's job is only to
    describe events that already happened and a score that's already computed;
    it should never need to invent or revise either."""

    id: str
    host_id: str
    risk_score: int
    technique_set: list[str]
    events: list[Event] = field(default_factory=list)

    def raw_log(self) -> str:
        """The naive serialization: every event as a plain line, joined. This
        is exactly what a rushed "just concatenate the telemetry into the
        prompt" implementation would produce."""
        return "\n".join(e.as_line() for e in self.events)
