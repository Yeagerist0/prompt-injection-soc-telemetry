"""Re-judge saved narrator outputs without calling the API again.

    python -m eval.rescore                     # newest run
    python -m eval.rescore eval/results/run_X.json

Every run file stores each tier's full narrator_output, so a change to
eval.judge can be evaluated against real responses for free. This matters
more than convenience: when a judge bug is found after a run, the choice is
otherwise between re-paying for 198 calls and shipping numbers you no longer
trust. It also makes judge changes auditable - you can show exactly which
verdicts moved and why.

Writes `<run>.rescored.json` and prints the before/after comparison.
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from eval.harness import RunResult, TIERS, summarize
from eval.judge import score
from eval.run_all import format_summary_table
from injection_corpus.loader import load_corpus


def rescore_file(path: Path) -> tuple[dict, dict, dict]:
    data = json.loads(path.read_text())
    corpus = {payload.id: payload for payload in load_corpus()}

    old_results: dict[str, list[RunResult]] = {}
    new_results: dict[str, list[RunResult]] = {}
    for tier, rows in data["results"].items():
        old_rows, new_rows = [], []
        for row in rows:
            old = RunResult(**row)
            old_rows.append(old)
            payload = corpus.get(old.payload_id)
            if payload is None:
                new_rows.append(old)
                continue
            judged = score(payload, old.narrator_output)
            new_rows.append(
                RunResult(
                    payload_id=old.payload_id,
                    category=old.category,
                    goal=old.goal,
                    narrator_output=old.narrator_output,
                    bypass_detected=judged.bypass_detected,
                    reason=judged.reason,
                )
            )
        old_results[tier] = old_rows
        new_results[tier] = new_rows
    return data, old_results, new_results


def changed_verdicts(old: list[RunResult], new: list[RunResult]) -> list[tuple[RunResult, RunResult]]:
    by_id = {r.payload_id: r for r in new}
    return [
        (o, by_id[o.payload_id])
        for o in old
        if o.payload_id in by_id and by_id[o.payload_id].bypass_detected != o.bypass_detected
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", nargs="?", help="run_*.json (default: newest)")
    parser.add_argument("--show", type=int, default=3, help="example changed verdicts per tier")
    args = parser.parse_args(argv)

    if args.run:
        path = Path(args.run)
    else:
        candidates = sorted(glob.glob("eval/results/run_*.json"))
        candidates = [c for c in candidates if not c.endswith(".rescored.json")]
        if not candidates:
            print("no eval/results/run_*.json found", file=sys.stderr)
            return 1
        path = Path(candidates[-1])

    data, old_results, new_results = rescore_file(path)
    old_summaries = {t: summarize(r) for t, r in old_results.items()}
    new_summaries = {t: summarize(r) for t, r in new_results.items()}

    print(f"rescored {path.name}   model={data.get('model')}   backend={data.get('backend')}\n")
    print("BEFORE (judge as it was when the run happened)")
    print(format_summary_table(old_summaries))
    print("\nAFTER (current judge)")
    print(format_summary_table(new_summaries))

    print("\nverdict changes")
    for tier in TIERS:
        changes = changed_verdicts(old_results.get(tier, []), new_results.get(tier, []))
        flipped_off = sum(1 for o, n in changes if o.bypass_detected and not n.bypass_detected)
        flipped_on = sum(1 for o, n in changes if not o.bypass_detected and n.bypass_detected)
        print(f"  {tier:<11} {len(changes):>3} changed  ({flipped_off} no-longer-bypass, {flipped_on} newly-bypass)")
        for _old, new in changes[: args.show]:
            print(f"      {new.payload_id}: {new.reason[:88]}")

    out = path.with_suffix(".rescored.json")
    out.write_text(
        json.dumps(
            {
                "rescored_at": datetime.now(timezone.utc).isoformat(),
                "source_run": path.name,
                "model": data.get("model"),
                "backend": data.get("backend"),
                "summaries": new_summaries,
                "previous_summaries": old_summaries,
                "results": {t: [asdict(r) for r in rs] for t, rs in new_results.items()},
            },
            indent=2,
        )
    )
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
