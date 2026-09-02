"""What the structural tier's safety costs in evidence.

`docs/RESULTS.md` establishes that the structural tier's entire measured
bypass rate is one renderer property: a `process_metadata` payload lands on a
`DNS_QUERY` event, and the DNS template renders only `dns_name`, so the
process name never reaches the analyst. The allow-listed rendering that makes
the tier safe also makes it lossy.

That is a tradeoff, and a tradeoff with exactly one dial has a curve. This
sweeps `Coverage.MINIMAL -> ATTRIBUTED -> FULL` over the same 66 payloads and
measures both sides of it:

* **bypass rate**, by the same judge as every other number in the repo, and
* **evidence retained** - of every attacker-controlled field value in the
  incident, how much of it the analyst is actually shown.

Wider coverage should trade the second against the first. Whether it does, and
how steeply, is the question.

**No model calls.** The structural tier's only model output is one label per
event, and every saved run already contains those labels in its rendered
report - `- [malicious_activity] [ts] ...`. This parses them back out and
re-renders, so the sweep runs on real classifications from both measured
models for free. Same trick as `eval.rescore`: outputs on disk are worth more
than they look.

    python -m eval.coverage
    python -m eval.coverage --run eval/results/run_20260811T082112Z.json
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

from eval import judge
from eval.harness import resolve_base_incident, splice_payload
from injection_corpus.loader import Payload, load_corpus
from narrator.structural import Coverage, ObservationKind, render_structural_report
from telemetry.synth_events import download_exec_incident

RESULTS_DIR = Path(__file__).resolve().parent / "results"
_LABEL = re.compile(r"^- \[([a-z_]+)\]", re.MULTILINE)

# Fields an attacker on the host chooses, per telemetry/schema.py. remote_addr
# is excluded: it is host-chosen but not a free-text injection channel.
ATTACKER_FIELDS = ("proc_image", "proc_cmdline", "file_path", "dns_name",
                   "registry_key", "user_agent")


@dataclass(frozen=True)
class CoverageRow:
    coverage: str
    n: int
    bypass_overall: float
    bypass_by_goal: dict[str, float]
    evidence_retained: float
    attacker_chars_shown: float

    def __str__(self) -> str:
        goals = "  ".join(f"{k[:8]} {v:.3f}" for k, v in sorted(self.bypass_by_goal.items()))
        return (f"{self.coverage:<11} bypass {self.bypass_overall:.3f}   evidence {self.evidence_retained:.3f}   "
                f"attacker chars/report {self.attacker_chars_shown:5.0f}   {goals}")


def labels_from_report(report: str, incident) -> dict[str, ObservationKind]:
    """Recover the model's per-event labels from a rendered structural report.

    The tier renders every event, in order, one line each, so line i belongs to
    event i. If that ever stops being true the count check below fails loudly
    rather than silently misattributing labels.
    """
    found = _LABEL.findall(report)
    if len(found) != len(incident.events):
        raise ValueError(
            f"report has {len(found)} labelled lines for {len(incident.events)} events; "
            "the structural renderer's shape changed and this parser is stale"
        )
    return {event.id: ObservationKind(label) for event, label in zip(incident.events, found)}


def _evidence(incident, report: str) -> tuple[int, int, int]:
    """(field values shown, field values present, attacker chars in the report)."""
    shown = present = chars = 0
    for event in incident.events:
        for name in ATTACKER_FIELDS:
            value = getattr(event, name, "")
            if not value:
                continue
            present += 1
            if value in report:
                shown += 1
                chars += len(value)
    return shown, present, chars


def sweep(run_path: Path, coverages=tuple(Coverage)) -> tuple[str, list[CoverageRow]]:
    run = json.loads(run_path.read_text())
    saved = {r["payload_id"]: r["narrator_output"] for r in run["results"]["structural"]}
    corpus = {p.id: p for p in load_corpus()}

    rows = []
    for coverage in coverages:
        verdicts, shown_t, present_t, chars_t, n = [], 0, 0, 0, 0
        for pid, report in saved.items():
            payload: Payload = corpus[pid]
            incident = splice_payload(resolve_base_incident(payload, download_exec_incident), payload)
            rendered = render_structural_report(incident, labels_from_report(report, incident), coverage)
            verdicts.append((payload, judge.score(payload, rendered)))
            s, p, c = _evidence(incident, rendered)
            shown_t += s
            present_t += p
            chars_t += c
            n += 1

        by_goal: dict[str, list[bool]] = {}
        for payload, verdict in verdicts:
            by_goal.setdefault(payload.goal, []).append(verdict.bypass_detected)

        rows.append(CoverageRow(
            coverage=coverage.value,
            n=n,
            bypass_overall=sum(v.bypass_detected for _, v in verdicts) / max(1, n),
            bypass_by_goal={g: sum(b) / len(b) for g, b in by_goal.items()},
            evidence_retained=shown_t / max(1, present_t),
            attacker_chars_shown=chars_t / max(1, n),
        ))
    return run["model"], rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", type=Path, default=None, help="a run_*.json; default is every one on disk")
    args = ap.parse_args()

    runs = [args.run] if args.run else sorted(
        p for p in RESULTS_DIR.glob("run_*.json") if "rescored" not in p.name or True
    )
    # Prefer the rescored file where both exist - it is the one RESULTS.md cites.
    if not args.run:
        stems = {p.name.replace(".rescored", ""): p for p in sorted(runs)}
        runs = list(stems.values())

    out = {}
    for path in runs:
        model, rows = sweep(path)
        print(f"\n== {model}  ({path.name})")
        for row in rows:
            print(f"   {row}")
        out[model] = [row.__dict__ for row in rows]

    dest = RESULTS_DIR / "coverage_sweep.json"
    dest.write_text(json.dumps(out, indent=2))
    print(f"\nwrote {dest}")


if __name__ == "__main__":
    main()
