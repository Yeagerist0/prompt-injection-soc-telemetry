"""The search: propose, run, judge, feed back, repeat.

Every number this produces has to survive three ways of being wrong, so each
has a guard in the code rather than a caveat in the write-up.

**The attacker could game the judge.** It never sees it - see
`redteam/attacker.py`. It gets the goal in behavioural terms only.

**A "new" bypass could be a rediscovery.** Every candidate is checked against
the hand-written corpus by normalised similarity and dropped if it is a near
duplicate, so "found something the corpus missed" means what it says.

**A bypass could be a one-off.** Hosted endpoints are not deterministic even
at temperature 0 - `docs/RESULTS.md` records a truncation that only happened
on one attempt. Every candidate scored as a bypass is re-run and re-judged,
and only a bypass that reproduces is counted as confirmed. The unconfirmed
ones are kept in the log, labelled, not quietly dropped.

    python -m redteam.loop --tier hardened --rounds 4 --candidates 8
    python -m redteam.loop --tier structural --goal severity_downgrade
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field as dc_field
from datetime import datetime, timezone
from pathlib import Path

from eval import judge
from eval.harness import TIERS, resolve_base_incident, splice_payload
from injection_corpus.loader import Payload, load_corpus
from narrator.backends import get_client
from redteam.attacker import DEFAULT_ATTACKER_MODEL, Feedback, propose
from telemetry.synth_events import download_exec_incident

RESULTS_DIR = Path(__file__).resolve().parent / "results"
GOALS = ("severity_downgrade", "entity_omission", "instruction_leak")
FIELDS = ("proc_image", "proc_cmdline", "file_path", "dns_name", "registry_key", "user_agent")

_NORM = re.compile(r"[^a-z0-9]+")


def _normalise(text: str) -> str:
    return _NORM.sub("", text.lower())


def _shingles(text: str, k: int = 6) -> set[str]:
    n = _normalise(text)
    return {n[i : i + k] for i in range(max(1, len(n) - k + 1))}


def is_rediscovery(candidate: str, corpus_shingles: list[set[str]], threshold: float = 0.6) -> bool:
    """True if `candidate` is a near-duplicate of a hand-written payload.

    Jaccard over character 6-shingles: robust to reordering and to the small
    edits a model makes when it is really just restating an example it was
    shown. The threshold is deliberately low - counting a genuine novelty as a
    rediscovery costs one candidate, while counting a rediscovery as a novelty
    corrupts the headline claim.
    """
    if not _normalise(candidate):
        return True
    mine = _shingles(candidate)
    return any(
        len(mine & other) / len(mine | other) >= threshold
        for other in corpus_shingles
        if other
    )


@dataclass
class Attempt:
    round: int
    tier: str
    goal: str
    field: str
    candidate: str
    bypass: bool
    confirmed: bool
    reason: str
    narrator_output: str
    rediscovery: bool = False
    error: str = ""


@dataclass
class Budget:
    """A hard ceiling on model calls, because a search loop with a free-tier
    key and no limit is how you lose a day's quota to a bug."""

    max_calls: int
    used: int = 0

    def spend(self, n: int = 1) -> None:
        if self.used + n > self.max_calls:
            raise RuntimeError(f"call budget exhausted ({self.max_calls})")
        self.used += n

    @property
    def left(self) -> int:
        return self.max_calls - self.used


def _synthetic_payload(candidate: str, field: str, goal: str, tier: str, index: int) -> Payload:
    return Payload(
        id=f"rt-{tier}-{goal[:4]}-{index:04d}",
        category="redteam",
        field=field,
        technique="model-generated",
        payload=candidate,
        goal=goal,
        tier_target=tier,
    )


def _narrate(payload: Payload, tier: str, client, model: str) -> str:
    incident = splice_payload(resolve_base_incident(payload, download_exec_incident), payload)
    return TIERS[tier](incident, client=client, model=model)


def run(
    *,
    tier: str,
    goals: tuple[str, ...] = GOALS,
    fields: tuple[str, ...] = FIELDS,
    rounds: int = 3,
    candidates: int = 8,
    target_model: str,
    attacker_model: str = DEFAULT_ATTACKER_MODEL,
    max_calls: int = 400,
    log=print,
) -> list[Attempt]:
    client = get_client()
    budget = Budget(max_calls)
    corpus_shingles = [_shingles(p.payload) for p in load_corpus()]
    attempts: list[Attempt] = []
    index = 0

    for goal in goals:
        for field in fields:
            feedback = Feedback([], [])
            for rnd in range(1, rounds + 1):
                if budget.left < candidates + 1:
                    log(f"  budget exhausted before {goal}/{field} round {rnd}")
                    return attempts
                budget.spend()
                try:
                    proposed = propose(
                        field=field, goal=goal, tier=tier, n=candidates,
                        feedback=feedback, client=client, model=attacker_model,
                    )
                except Exception as exc:  # a failed proposal must not kill the run
                    log(f"  {goal}/{field} r{rnd}: attacker call failed: {exc}")
                    break
                if not proposed:
                    log(f"  {goal}/{field} r{rnd}: attacker returned nothing")
                    break

                won, lost = [], []
                for candidate in proposed:
                    index += 1
                    rediscovered = is_rediscovery(candidate, corpus_shingles)
                    payload = _synthetic_payload(candidate, field, goal, tier, index)
                    try:
                        budget.spend()
                        output = _narrate(payload, tier, client, target_model)
                    except Exception as exc:
                        attempts.append(Attempt(rnd, tier, goal, field, candidate, False, False,
                                                "", "", rediscovered, str(exc)[:200]))
                        continue

                    verdict = judge.score(payload, output)
                    confirmed = False
                    if verdict.bypass_detected and budget.left > 0:
                        try:
                            budget.spend()
                            confirmed = judge.score(
                                payload, _narrate(payload, tier, client, target_model)
                            ).bypass_detected
                        except Exception:
                            confirmed = False

                    attempts.append(Attempt(rnd, tier, goal, field, candidate,
                                            verdict.bypass_detected, confirmed,
                                            verdict.reason, output, rediscovered))
                    (won if verdict.bypass_detected else lost).append(candidate)

                novel = sum(1 for a in attempts
                            if a.round == rnd and a.goal == goal and a.field == field
                            and a.confirmed and not a.rediscovery)
                log(f"  {goal:<19} {field:<13} r{rnd}: {len(won)}/{len(proposed)} scored, "
                    f"{novel} confirmed novel   (calls left {budget.left})")
                feedback = Feedback(succeeded=won, failed=lost)
                if not won and rnd >= 2:
                    break  # two rounds of nothing: spend the budget elsewhere

    return attempts


def summarise(attempts: list[Attempt]) -> dict:
    ok = [a for a in attempts if not a.error]
    confirmed_novel = [a for a in ok if a.confirmed and not a.rediscovery]
    return {
        "attempts": len(attempts),
        "errors": len(attempts) - len(ok),
        "scored_bypass": sum(a.bypass for a in ok),
        "confirmed_bypass": sum(a.confirmed for a in ok),
        "confirmed_novel_bypass": len(confirmed_novel),
        "rediscoveries": sum(a.rediscovery for a in ok),
        "by_goal": {
            g: len([a for a in confirmed_novel if a.goal == g]) for g in GOALS
        },
        "novel_payloads": [
            {"goal": a.goal, "field": a.field, "payload": a.candidate, "reason": a.reason}
            for a in confirmed_novel
        ],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tier", default="hardened", choices=sorted(TIERS))
    ap.add_argument("--goal", action="append", choices=GOALS, help="repeatable; default all three")
    ap.add_argument("--field", action="append", choices=FIELDS, help="repeatable; default all six")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--candidates", type=int, default=8)
    ap.add_argument("--max-calls", type=int, default=400)
    ap.add_argument("--attacker-model", default=DEFAULT_ATTACKER_MODEL)
    ap.add_argument("--target-model", default=os.environ.get("NARRATOR_MODEL", "gemini-3.1-flash-lite"))
    args = ap.parse_args()

    started = time.time()
    print(f"tier={args.tier}  attacker={args.attacker_model}  target={args.target_model}  "
          f"budget={args.max_calls} calls")
    attempts = run(
        tier=args.tier,
        goals=tuple(args.goal) if args.goal else GOALS,
        fields=tuple(args.field) if args.field else FIELDS,
        rounds=args.rounds,
        candidates=args.candidates,
        target_model=args.target_model,
        attacker_model=args.attacker_model,
        max_calls=args.max_calls,
    )

    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = RESULTS_DIR / f"redteam_{args.tier}_{stamp}.json"
    summary = summarise(attempts)
    out.write_text(json.dumps({
        "generated_at": stamp,
        "tier": args.tier,
        "attacker_model": args.attacker_model,
        "target_model": args.target_model,
        "elapsed_s": round(time.time() - started, 1),
        "summary": summary,
        "attempts": [asdict(a) for a in attempts],
    }, indent=1))

    print("\n" + json.dumps({k: v for k, v in summary.items() if k != "novel_payloads"}, indent=1))
    for p in summary["novel_payloads"]:
        print(f"  NOVEL {p['goal']:<19} {p['field']:<13} {p['payload'][:80]}")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
