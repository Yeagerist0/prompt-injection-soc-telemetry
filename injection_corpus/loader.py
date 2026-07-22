"""Loads and validates injection_corpus/payloads.yaml."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

Category = Literal["process_metadata", "file_path", "network_artifact", "log_string"]
Field = Literal["proc_image", "file_path", "dns_name", "proc_cmdline"]
Goal = Literal["severity_downgrade", "entity_omission", "instruction_leak"]

_VALID_CATEGORY_FIELD = {
    "process_metadata": "proc_image",
    "file_path": "file_path",
    "network_artifact": "dns_name",
    "log_string": "proc_cmdline",
}

_CORPUS_PATH = Path(__file__).parent / "payloads.yaml"


@dataclass(frozen=True)
class Payload:
    id: str
    category: Category
    field: Field
    technique: str
    payload: str
    goal: Goal


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
        out.append(Payload(**{k: e[k] for k in ("id", "category", "field", "technique", "payload", "goal")}))
    return out


def by_category(payloads: list[Payload]) -> dict[str, list[Payload]]:
    out: dict[str, list[Payload]] = {}
    for p in payloads:
        out.setdefault(p.category, []).append(p)
    return out
