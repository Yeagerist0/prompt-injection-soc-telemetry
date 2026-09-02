"""Runs every model against every split and writes one results file.

Protocol, fixed before any numbers were looked at:

* Fit on `train` only. Select on `val`.
* Choose one operating threshold per model, on `val`, at a 1% false-positive
  rate. Apply that same threshold to every test split.
* Report three test splits that ask progressively harder questions:
  `test_seen` (new strings, known techniques), `test_unseen` (techniques held
  out of training entirely), and `test_human` (the 66 hand-written corpus
  payloads, written months before this detector existed).
* Report the length-only control alongside every model on every split. A model
  that does not clearly beat it has not learned what it appears to have
  learned.

    python -m detector.experiment            # all models
    python -m detector.experiment --fast     # skip the transformer
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from detector.classical import CharNgram, LengthOnly
from detector.dataset import Split, build, summarise
from detector.metrics import Report, evaluate, threshold_at_fpr

RESULTS_DIR = Path(__file__).resolve().parent / "results"
TARGET_FPR = 0.01
TEST_SPLITS = ("test_seen", "test_unseen", "test_human")


def _hard_mask(split: Split) -> np.ndarray:
    return np.array([e.source == "benign_hard" for e in split.examples])


def _run_model(model, splits: dict[str, Split], log=print) -> dict:
    val = splits["val"]
    val_scores = model.score(val.texts)
    threshold = threshold_at_fpr(val_scores, np.array(val.labels), TARGET_FPR)

    reports: list[Report] = [
        evaluate("val", val_scores, np.array(val.labels), threshold, _hard_mask(val))
    ]
    per_family: dict[str, dict[str, float]] = {}
    for name in TEST_SPLITS:
        split = splits[name]
        scores = model.score(split.texts)
        reports.append(evaluate(name, scores, np.array(split.labels), threshold, _hard_mask(split)))
        for i, ex in enumerate(split.examples):
            if ex.label == 1:
                bucket = per_family.setdefault(ex.source, {"n": 0, "caught": 0})
                bucket["n"] += 1
                bucket["caught"] += int(scores[i] >= threshold)

    for r in reports:
        log(f"    {r}")
    return {
        "model": model.name,
        "threshold": threshold,
        "reports": [r.as_dict() for r in reports],
        "recall_by_family": {
            k: {"n": v["n"], "caught": v["caught"], "recall": round(v["caught"] / v["n"], 3)}
            for k, v in sorted(per_family.items())
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fast", action="store_true", help="skip the transformer fine-tune")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--seed", type=int, default=20260902)
    args = ap.parse_args()

    splits = build(seed=args.seed)
    print(summarise(splits))
    print()

    train, val = splits["train"], splits["val"]
    results = []

    for cls in (LengthOnly, CharNgram):
        model = cls()
        print(f"[{model.name}]")
        t0 = time.time()
        model.fit(train.texts, train.labels)
        print(f"    fit in {time.time() - t0:.1f}s")
        results.append(_run_model(model, splits))
        print()

    if not args.fast:
        from detector.transformer import TrainConfig, TransformerDetector

        model = TransformerDetector(TrainConfig(epochs=args.epochs, seed=args.seed))
        print(f"[{model.name}]")
        t0 = time.time()
        model.fit(train.texts, train.labels, val.texts, val.labels)
        print(f"    fit in {time.time() - t0:.1f}s")
        results.append(_run_model(model, splits))
        print()

    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = RESULTS_DIR / f"detector_{stamp}.json"
    out.write_text(json.dumps({
        "generated_at": stamp,
        "seed": args.seed,
        "target_fpr": TARGET_FPR,
        "splits": {name: {"n": len(s), "n_pos": sum(s.labels), "lengths": s.length_stats()}
                   for name, s in splits.items()},
        "held_out_families": list(__import__("detector.families", fromlist=["HELD_OUT"]).HELD_OUT),
        "results": results,
    }, indent=2))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
