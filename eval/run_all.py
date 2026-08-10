"""CLI entry point: run the full injection corpus through every narrator
tier and write results to eval/results/.

This is the only piece of the project that costs money - each tier makes
real Claude API calls (66 payloads x 3 tiers = 198 short calls total, well
under $1 even on Opus, pennies on Haiku). Everything else (corpus, harness,
judge, all three narrator tiers, dashboard) is already built and unit-tested
against fixture narrators with no API access required.

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
from narrator.backends import describe_backend

RESULTS_DIR = Path(__file__).parent / "results"
_GOALS = ("severity_downgrade", "entity_omission", "instruction_leak")


# Leading characters that make Excel / LibreOffice / Sheets treat a cell as a
# formula. Every string column in this export carries attacker-authored text
# (payload ids come from the corpus YAML; judge reasons quote payload-derived
# entity markers verbatim), so the export is a genuine injection sink.
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: object) -> object:
    """Neutralize spreadsheet formula injection in a CSV cell.

    Prefixes a single quote to any string that would otherwise be parsed as
    a formula on open. Non-strings pass through untouched. This project's
    whole subject is untrusted strings reaching a consumer that interprets
    them - shipping a results export that hands `=cmd|'/C calc'!A0` to the
    analyst's spreadsheet would be the same bug one layer down.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_TRIGGERS):
        return "'" + value
    return value


def write_csv(path: Path, all_results: dict[str, list[RunResult]]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["tier", "payload_id", "category", "goal", "bypass_detected", "reason", "narrator_output"]
        )
        for tier, results in all_results.items():
            for r in results:
                writer.writerow(
                    csv_safe(v)
                    for v in (
                        tier,
                        r.payload_id,
                        r.category,
                        r.goal,
                        r.bypass_detected,
                        r.reason,
                        r.narrator_output,
                    )
                )


def write_json(
    path: Path,
    all_results: dict[str, list[RunResult]],
    summaries: dict[str, dict[str, float]],
    model: str,
    backend: str = "unknown",
) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": model,
        # Which provider served the run. A bypass rate is only interpretable
        # against a named model on a named endpoint.
        "backend": backend,
        "summaries": summaries,
        "results": {tier: [asdict(r) for r in results] for tier, results in all_results.items()},
    }
    path.write_text(json.dumps(payload, indent=2))


def load_checkpoint(path: Path) -> dict[str, dict[str, RunResult]]:
    """Rebuild {tier: {payload_id: RunResult}} from a checkpoint file.

    Tolerates a truncated final line: a process killed mid-write leaves one,
    and refusing to resume because of it would defeat the point.
    """
    prior: dict[str, dict[str, RunResult]] = {}
    if not path.exists():
        return prior
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        tier = record.pop("tier", None)
        if not tier:
            continue
        try:
            prior.setdefault(tier, {})[record["payload_id"]] = RunResult(**record)
        except TypeError:
            continue
    return prior


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

    backend = describe_backend()
    if backend == "none":
        print(
            "No model backend is configured - every tier makes real API calls.\n"
            "\n"
            "  Anthropic:         export ANTHROPIC_API_KEY=sk-...\n"
            "                     (bills Console API credit; a Claude.ai Pro/Max\n"
            "                     chat subscription does not include API usage)\n"
            "\n"
            "  Any OpenAI-compatible endpoint (Gemini compat layer, Groq,\n"
            "  OpenRouter, a local vLLM/llama.cpp server):\n"
            "                     export NARRATOR_API_KEY=...\n"
            "                     export NARRATOR_BASE_URL=https://host/v1\n"
            "                     export NARRATOR_MODEL=<model id>\n"
            "                     export NARRATOR_RPM=10   # pace a free tier",
            file=sys.stderr,
        )
        return 1

    if args.model:
        os.environ["NARRATOR_MODEL"] = args.model
    model = os.environ.get("NARRATOR_MODEL", "claude-opus-4-8")

    # A claude-* id sent to a non-Anthropic endpoint fails 198 times in a row.
    if backend.startswith("openai-compat") and model.startswith("claude-"):
        print(
            f"Refusing to run: backend is {backend} but the model is '{model}'.\n"
            "Set NARRATOR_MODEL (or --model) to a model that endpoint serves.",
            file=sys.stderr,
        )
        return 1

    def report_progress(tier: str, index: int, total: int, payload) -> None:
        print(f"[{tier:<10} {index:>3}/{total}] {payload.id}", flush=True)

    # Checkpoint every scored result as it lands. A run that dies at call 150
    # of 198 previously lost all 150; now it resumes, which matters most on a
    # metered free tier where those calls cannot simply be re-bought.
    RESULTS_DIR.mkdir(exist_ok=True)
    checkpoint = RESULTS_DIR / "checkpoint.jsonl"
    prior = load_checkpoint(checkpoint)
    resumed = sum(len(v) for v in prior.values())
    if resumed:
        print(f"resuming: {resumed} results recovered from {checkpoint.name}\n", flush=True)

    def record(tier: str, result: RunResult) -> None:
        with checkpoint.open("a") as f:
            f.write(json.dumps({"tier": tier, **asdict(result)}) + "\n")

    all_results = run_all_tiers(on_progress=report_progress, on_result=record, prior=prior)
    summaries = {tier: summarize(results) for tier, results in all_results.items()}

    RESULTS_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_path = RESULTS_DIR / f"run_{timestamp}.csv"
    json_path = RESULTS_DIR / f"run_{timestamp}.json"
    write_csv(csv_path, all_results)
    write_json(json_path, all_results, summaries, model, backend)

    print(f"backend: {backend}   model: {model}\n")
    print(format_summary_table(summaries))
    print(f"\nWrote {csv_path} and {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
