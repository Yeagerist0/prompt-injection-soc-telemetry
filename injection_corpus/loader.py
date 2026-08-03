"""Loads and validates injection_corpus/payloads.yaml."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

Category = Literal[
    "process_metadata",
    "file_path",
    "network_artifact",
    "log_string",
    "registry_artifact",
    "http_artifact",
]
Field = Literal["proc_image", "file_path", "dns_name", "proc_cmdline", "registry_key", "user_agent"]
Goal = Literal["severity_downgrade", "entity_omission", "instruction_leak"]

_VALID_CATEGORY_FIELD = {
    "process_metadata": "proc_image",
    "file_path": "file_path",
    "network_artifact": "dns_name",
    "log_string": "proc_cmdline",
    "registry_artifact": "registry_key",
    "http_artifact": "user_agent",
}

_CORPUS_PATH = Path(__file__).parent / "payloads.yaml"


TierTarget = Literal["generic", "hardened", "structural"]
_VALID_TIER_TARGETS = {"generic", "hardened", "structural"}


@dataclass(frozen=True)
class Payload:
    id: str
    category: Category
    field: Field
    technique: str
    payload: str
    goal: Goal
    # Which defense this payload is specifically engineered against.
    # "generic" payloads try to fool any narrator; "hardened" ones target the
    # tier-2 escaping/JSON-schema design; "structural" ones try to steer the
    # tier-3 allow-list label itself, which is the only lever tier 3 leaves
    # the model. Optional in YAML, defaults to "generic".
    tier_target: TierTarget = "generic"


def load_corpus(path: Path = _CORPUS_PATH) -> list[Payload]:
    """Parse and validate the corpus. Raises ValueError on any malformed or
    inconsistent entry rather than silently skipping it — a corrupted corpus
    entry would silently shrink the eval's coverage without anyone noticing."""
    raw = yaml.safe_load(path.read_text())
    entries = raw.get("payloads", [])
    if not entries:
        raise ValueError(f"{path}: no payloads found")

    seen_ids: set[str] = set()
    out: list[Payload] = []
    for i, e in enumerate(entries):
        missing = {"id", "category", "field", "technique", "payload", "goal"} - e.keys()
        if missing:
            raise ValueError(f"{path}: entry {i} missing fields {missing}: {e}")
        if e["id"] in seen_ids:
            raise ValueError(f"{path}: duplicate payload id {e['id']!r}")
        seen_ids.add(e["id"])
        if e["category"] not in _VALID_CATEGORY_FIELD:
            raise ValueError(f"{path}: entry {e['id']} has unknown category {e['category']!r}")
        if e["field"] != _VALID_CATEGORY_FIELD[e["category"]]:
            raise ValueError(
                f"{path}: entry {e['id']} category {e['category']!r} must target field "
                f"{_VALID_CATEGORY_FIELD[e['category']]!r}, got {e['field']!r}"
            )
        tier_target = e.get("tier_target", "generic")
        if tier_target not in _VALID_TIER_TARGETS:
            raise ValueError(
                f"{path}: entry {e['id']} has unknown tier_target {tier_target!r} "
                f"(expected one of {sorted(_VALID_TIER_TARGETS)})"
            )
        fields = {k: e[k] for k in ("id", "category", "field", "technique", "payload", "goal")}
        out.append(Payload(**fields, tier_target=tier_target))
    return out


def by_category(payloads: list[Payload]) -> dict[str, list[Payload]]:
    out: dict[str, list[Payload]] = {}
    for p in payloads:
        out.setdefault(p.category, []).append(p)
    return out
