"""CLI entry point: run the full injection corpus through every narrator
tier and write results to eval/results/.

This is the only piece of the project that costs money - each tier makes
real Claude API calls (40 payloads x 3 tiers = 120 short calls total, well
under $1 even on Opus, pennies on Haiku). Everything else (corpus, harness,
judge, all three narrator tiers) is already built and unit-tested against
fixture narrators with no API access required.

Usage:
    ANTHROPIC_API_KEY=sk-... python -m eval.run_all
    ANTHROPIC_API_KEY=sk-... python -m eval.run_all --model claude-haiku-4-5
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from eval.harness import RunResult, TIERS, run_all_tiers, summarize

RESULTS_DIR = Path(__file__).parent / "results"
_GOALS = ("severity_downgrade", "entity_omission", "instruction_leak")


def write_csv(path: Path, all_results: dict[str, list[RunResult]]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["tier", "payload_id", "category", "goal", "bypass_detected", "reason"])
        for tier, results in all_results.items():
            for r in results:
                writer.writerow([tier, r.payload_id, r.category, r.goal, r.bypass_detected, r.reason])


def write_json(
    path: Path,
    all_results: dict[str, list[RunResult]],
    summaries: dict[str, dict[str, float]],
    model: str,
) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "summaries": summaries,
        "results": {tier: [asdict(r) for r in results] for tier, results in all_results.items()},
    }
    path.write_text(json.dumps(payload, indent=2))


def format_summary_table(summaries: dict[str, dict[str, float]]) -> str:
    header = f"{'tier':<12} {'overall':>10}  " + "  ".join(f"{g:>20}" for g in _GOALS)
    rows = [header, "-" * len(header)]
    for tier in TIERS:
        s = summaries.get(tier, {})
        cells = "  ".join(f"{s.get(g, 0):>20.0%}" for g in _GOALS)
        rows.append(f"{tier:<12} {s.get('overall', 0):>10.0%}  {cells}")
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=None, help="Override NARRATOR_MODEL for this run")
    args = parser.parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print(
            "ANTHROPIC_API_KEY is not set - every tier makes real Claude API calls.\n"
            "Set it, or run `ant auth login` first if you have Claude Code / Claude "
            "Pro-Max OAuth access instead of a metered key, then re-run this command.",
            file=sys.stderr,
        )
        return 1

    if args.model:
        os.environ["NARRATOR_MODEL"] = args.model
    model = os.environ.get("NARRATOR_MODEL", "claude-opus-4-8")

    all_results = run_all_tiers()
    summaries = {tier: summarize(results) for tier, results in all_results.items()}

    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_path = RESULTS_DIR / f"run_{timestamp}.csv"
    json_path = RESULTS_DIR / f"run_{timestamp}.json"
    write_csv(csv_path, all_results)
    write_json(json_path, all_results, summaries, model)

    print(format_summary_table(summaries))
    print(f"\nWrote {csv_path} and {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
