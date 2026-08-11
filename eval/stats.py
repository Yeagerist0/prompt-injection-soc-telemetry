"""Uncertainty for the bypass rates, from the results already on disk.

A single bypass rate with no interval is easy to over-read: 6% and 8% from 66
payloads are not obviously different numbers. This module quantifies the
variation that actually exists in the design.

The variation is *across payloads*, not across samples. The eval runs at
temperature 0, so re-running a payload returns the same completion and the
same verdict - repeated sampling would produce identical numbers and false
confidence, not a confidence interval. What is uncertain is which 66 payloads
the corpus happens to contain, and a bootstrap over payloads answers exactly
that.

Tier comparisons are **paired**: every tier sees the same payloads, so a
resample must draw the same payload indices for both tiers. Bootstrapping each
tier independently would inflate the interval on their difference by throwing
away the pairing.

Stdlib only, deliberately - this repo has no numeric dependency and a
bootstrap over 66 items does not justify adding one.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

DEFAULT_RESAMPLES = 10000


@dataclass(frozen=True)
class Interval:
    point: float
    lo: float
    hi: float

    def __str__(self) -> str:
        return f"{self.point:.1%} [{self.lo:.1%}, {self.hi:.1%}]"

    @property
    def excludes_zero(self) -> bool:
        return self.lo > 0 or self.hi < 0


def _percentiles(values: list[float], alpha: float) -> tuple[float, float]:
    """Percentile bounds by nearest-rank on the sorted resample distribution."""
    ordered = sorted(values)
    n = len(ordered)
    lo_i = max(0, min(n - 1, int(round((alpha / 2) * (n - 1)))))
    hi_i = max(0, min(n - 1, int(round((1 - alpha / 2) * (n - 1)))))
    return ordered[lo_i], ordered[hi_i]


def bootstrap_rate(
    flags: list[bool], *, resamples: int = DEFAULT_RESAMPLES, seed: int = 0, alpha: float = 0.05
) -> Interval:
    """Percentile bootstrap CI for a single tier's bypass rate."""
    n = len(flags)
    if n == 0:
        return Interval(0.0, 0.0, 0.0)
    observations = [1.0 if f else 0.0 for f in flags]
    point = sum(observations) / n
    rng = random.Random(seed)
    rates = []
    for _ in range(resamples):
        total = 0.0
        for _ in range(n):
            total += observations[rng.randrange(n)]
        rates.append(total / n)
    lo, hi = _percentiles(rates, alpha)
    return Interval(point, lo, hi)


def bootstrap_paired_difference(
    flags_a: list[bool],
    flags_b: list[bool],
    *,
    resamples: int = DEFAULT_RESAMPLES,
    seed: int = 0,
    alpha: float = 0.05,
) -> Interval:
    """Percentile bootstrap CI for (rate_a - rate_b) on paired payloads.

    Both lists must be ordered by the same payload ids. An interval excluding
    zero is the claim "these tiers differ"; one spanning zero says this corpus
    cannot separate them - a result worth stating rather than papering over
    with two bare percentages.
    """
    if len(flags_a) != len(flags_b):
        raise ValueError(f"paired bootstrap needs equal-length inputs, got {len(flags_a)} and {len(flags_b)}")
    n = len(flags_a)
    if n == 0:
        return Interval(0.0, 0.0, 0.0)
    a = [1.0 if f else 0.0 for f in flags_a]
    b = [1.0 if f else 0.0 for f in flags_b]
    point = sum(a) / n - sum(b) / n
    rng = random.Random(seed)
    diffs = []
    for _ in range(resamples):
        total_a = total_b = 0.0
        for _ in range(n):
            i = rng.randrange(n)
            total_a += a[i]
            total_b += b[i]
        diffs.append((total_a - total_b) / n)
    lo, hi = _percentiles(diffs, alpha)
    return Interval(point, lo, hi)


def aligned_flags(results: dict[str, list], tier_a: str, tier_b: str) -> tuple[list[bool], list[bool]]:
    """Return bypass flags for two tiers, ordered by their shared payload ids."""
    by_id_a = {r["payload_id"]: bool(r["bypass_detected"]) for r in results[tier_a]}
    by_id_b = {r["payload_id"]: bool(r["bypass_detected"]) for r in results[tier_b]}
    shared = sorted(set(by_id_a) & set(by_id_b))
    return [by_id_a[i] for i in shared], [by_id_b[i] for i in shared]


def _main(argv: list[str] | None = None) -> int:
    """CLI: `python -m eval.stats [run.json]` - costs no API calls."""
    import argparse
    import glob
    import json
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Bootstrap CIs for a saved run.")
    parser.add_argument("run", nargs="?", help="run_*.json (default: newest, preferring rescored)")
    parser.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args(argv)

    if args.run:
        path = Path(args.run)
    else:
        rescored = sorted(glob.glob("eval/results/*.rescored.json"))
        plain = [p for p in sorted(glob.glob("eval/results/run_*.json")) if not p.endswith(".rescored.json")]
        candidates = rescored or plain
        if not candidates:
            print("no eval/results/run_*.json found", file=sys.stderr)
            return 1
        path = Path(candidates[-1])

    data = json.loads(path.read_text())
    results = data["results"]
    tiers = [t for t in ("naive", "hardened", "structural") if t in results]

    n = len(results[tiers[0]]) if tiers else 0
    print(f"{path.name}   model={data.get('model')}   n={n} payloads")
    print(f"bootstrap over payloads, {args.resamples:,} resamples, 95% percentile CI\n")
    print(f"{'tier':<12} {'bypass rate [95% CI]'}")
    print("-" * 42)
    for tier in tiers:
        flags = [bool(r["bypass_detected"]) for r in results[tier]]
        print(f"{tier:<12} {bootstrap_rate(flags, resamples=args.resamples, seed=args.seed)}")

    print("\npaired differences")
    print("-" * 66)
    for a, b in [(x, y) for i, x in enumerate(tiers) for y in tiers[i + 1 :]]:
        fa, fb = aligned_flags(results, a, b)
        interval = bootstrap_paired_difference(fa, fb, resamples=args.resamples, seed=args.seed)
        verdict = "separated" if interval.excludes_zero else "NOT separated by this corpus"
        print(f"{a:>11} - {b:<12} {str(interval):<30} {verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
