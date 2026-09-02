"""Assembles train/validation/test splits, and guards the three ways this
experiment could lie to itself.

1. **Technique leakage.** `test_unseen` contains only families that never
   appear in training, so it measures generalisation to a new technique
   rather than to new wording of a known one.
2. **String leakage.** Benign values are drawn from shared template pools,
   so any exact string that appears in training is removed from every test
   split. Without this, a duplicated negative is scored as a correct
   prediction on an example the model memorised.
3. **Length.** Injections are naturally longer than real field values. Each
   split records its per-class length distribution, and `controls.py` fits a
   classifier on length alone against the same splits. If the real model does
   not clearly beat that, it has learned to count characters.

`test_human` is the 66 hand-written payloads from `injection_corpus/` - built
months before this detector existed, by a person, not by these generators.
It is the only split not produced by the same code that produced training
data, and it is the number to believe.
"""
from __future__ import annotations

import random
import statistics
from dataclasses import dataclass, field as dc_field

from detector.benign import FIELDS, benign_values
from detector.families import FAMILIES, HELD_OUT, TRAIN_FAMILIES
from injection_corpus.loader import load_corpus


@dataclass(frozen=True)
class Example:
    text: str
    label: int          # 1 = instruction-carrying, 0 = benign
    field: str
    source: str         # family name, "corpus", "benign" or "benign_hard"


@dataclass
class Split:
    name: str
    examples: list[Example] = dc_field(default_factory=list)

    @property
    def texts(self) -> list[str]:
        return [e.text for e in self.examples]

    @property
    def labels(self) -> list[int]:
        return [e.label for e in self.examples]

    def length_stats(self) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = {}
        for label, key in ((1, "injected"), (0, "benign")):
            lens = [len(e.text) for e in self.examples if e.label == label]
            out[key] = {
                "n": len(lens),
                "mean": round(statistics.mean(lens), 1) if lens else 0.0,
                "median": statistics.median(lens) if lens else 0.0,
            }
        return out

    def __len__(self) -> int:
        return len(self.examples)


def _injections(families: tuple[str, ...], per_family: int, rng: random.Random) -> list[Example]:
    out = []
    for name in families:
        gen = FAMILIES[name]
        for _ in range(per_family):
            f = rng.choice(FIELDS)
            out.append(Example(gen(f, rng), 1, f, name))
    return out


def _benigns(n: int, rng: random.Random, pool: str) -> list[Example]:
    per = max(1, n // len(FIELDS))
    out = []
    for f in FIELDS:
        for value, is_hard in benign_values(f, per, rng=rng, pool=pool):
            out.append(Example(value, 0, f, "benign_hard" if is_hard else "benign"))
    return out


def _corpus_examples() -> list[Example]:
    return [Example(p.payload, 1, p.field, "corpus") for p in load_corpus()]


def build(seed: int = 20260902) -> dict[str, Split]:
    """Every split, with leakage already removed."""
    rng = random.Random(seed)

    train = Split("train")
    train.examples = _injections(TRAIN_FAMILIES, 130, rng) + _benigns(960, rng, "train")

    val = Split("val")
    val.examples = _injections(TRAIN_FAMILIES, 30, rng) + _benigns(240, rng, "val")

    seen = Split("test_seen")
    seen.examples = _injections(TRAIN_FAMILIES, 40, rng) + _benigns(600, rng, "test")

    unseen = Split("test_unseen")
    unseen.examples = _injections(HELD_OUT, 90, rng) + _benigns(600, rng, "test")

    human = Split("test_human")
    corpus = _corpus_examples()
    human.examples = corpus + _benigns(600, rng, "test")

    # Benign templates are already partitioned by pool, so this only has work
    # to do on the injection side, where train and test_seen share generators.
    seen_texts = {e.text for e in train.examples} | {e.text for e in val.examples}
    for split in (seen, unseen, human):
        split.examples = [e for e in split.examples if e.text not in seen_texts]
        deduped, within = [], set()
        for e in split.examples:
            if e.text not in within:
                within.add(e.text)
                deduped.append(e)
        split.examples = deduped

    return {s.name: s for s in (train, val, seen, unseen, human)}


def summarise(splits: dict[str, Split]) -> str:
    lines = [f"{'split':<12} {'n':>5} {'pos':>5} {'neg':>5} {'hard-neg':>9}  length mean (inj/benign)"]
    for name, s in splits.items():
        pos = sum(s.labels)
        hard = sum(1 for e in s.examples if e.source == "benign_hard")
        ls = s.length_stats()
        lines.append(
            f"{name:<12} {len(s):>5} {pos:>5} {len(s) - pos:>5} {hard:>9}  "
            f"{ls['injected']['mean']:.0f} / {ls['benign']['mean']:.0f}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(summarise(build()))
