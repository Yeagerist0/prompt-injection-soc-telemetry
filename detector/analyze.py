"""What each model missed, and what that says about where a detector fails.

The headline metrics say how much gets through. This says *which* attacks get
through, which is the part that transfers: a detector that misses a random 25%
is a tuning problem, and one that misses a specific shape of attack is a
design problem.

    python -m detector.analyze                 # newest scores file
    python -m detector.analyze --file <path>
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from injection_corpus.loader import load_corpus

RESULTS_DIR = Path(__file__).resolve().parent / "results"


def _newest() -> Path:
    files = sorted(RESULTS_DIR.glob("scores_*.json"))
    if not files:
        raise SystemExit("no scores_*.json in detector/results - run `python -m detector.experiment` first")
    return files[-1]


def _thresholds(scores: dict) -> dict[str, float]:
    """Recover each model's operating threshold from the validation rows the
    experiment recorded, so this script never picks its own."""
    run = RESULTS_DIR / _newest().name.replace("scores_", "detector_")
    if run.exists():
        return {r["model"]: r["threshold"] for r in json.loads(run.read_text())["results"]}
    raise SystemExit(f"missing {run}; thresholds must come from the run, not from this script")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", type=Path, default=None)
    args = ap.parse_args()

    path = args.file or _newest()
    data = json.loads(path.read_text())
    thresholds = _thresholds(data)
    corpus = {p.payload: p for p in load_corpus()}

    print(f"# {path.name}\n")

    for split_name, rows in data["splits"].items():
        by_model = defaultdict(list)
        for r in rows:
            by_model[r["model"]].append(r)

        print(f"## {split_name}")
        for model, model_rows in by_model.items():
            t = thresholds[model]
            fam = defaultdict(lambda: [0, 0])
            for r in model_rows:
                if r["label"] == 1:
                    fam[r["source"]][0] += 1
                    fam[r["source"]][1] += int(r["score"] >= t)
            line = "  ".join(f"{k} {v[1]}/{v[0]}" for k, v in sorted(fam.items()))
            print(f"  {model:<24} threshold {t:.3f}   {line}")
        print()

    print("## hand-written payloads missed, by model\n")
    human = data["splits"].get("test_human", [])
    by_model = defaultdict(list)
    for r in human:
        if r["label"] == 1 and r["score"] < thresholds[r["model"]]:
            by_model[r["model"]].append(r)

    for model, rows in by_model.items():
        print(f"### {model} — missed {len(rows)}")
        for r in sorted(rows, key=lambda x: x["score"]):
            p = corpus.get(r["text"])
            cat = p.category if p else "?"
            goal = p.goal if p else "?"
            pid = p.id if p else "?"
            print(f"  {pid:<7} {r['score']:.3f}  {cat:<18} {goal:<19} {r['text'][:70]}")
        print()

    caught_by_none = [
        r["text"] for r in human
        if r["label"] == 1 and all(
            row["score"] < thresholds[row["model"]]
            for row in human if row["text"] == r["text"]
        )
    ]
    unique = sorted(set(caught_by_none))
    print(f"## missed by every model: {len(unique)}\n")
    for text in unique:
        p = corpus.get(text)
        print(f"  {p.id if p else '?':<7} {text[:80]}")


if __name__ == "__main__":
    main()
