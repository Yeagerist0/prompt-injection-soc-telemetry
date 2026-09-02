"""Tests for the guards, not for the model.

Nothing here asserts a bypass rate or an accuracy. What these check is that
the experiment is still capable of producing an honest number: that the splits
do not leak, that the held-out techniques are actually held out, and that the
threshold rule keeps to the false-positive budget it claims. Those are the
properties that, when they quietly break, turn a null result into a
discovery.
"""
from __future__ import annotations

import random

import pytest

# The detector is an optional extra (pip install -e ".[detector]"). The rest of
# the repo runs without numpy or scikit-learn, so skip rather than fail
# collection when they are absent - same pattern as the API-gated tests in
# narrator/.
np = pytest.importorskip("numpy", reason="detector extras not installed")
pytest.importorskip("sklearn", reason="detector extras not installed")

from detector.benign import FIELDS, POOLS, benign_values  # noqa: E402
from detector.classical import CharNgram, LengthOnly  # noqa: E402
from detector.dataset import build  # noqa: E402
from detector.families import FAMILIES, HELD_OUT, TRAIN_FAMILIES  # noqa: E402
from detector.metrics import threshold_at_fpr  # noqa: E402
from injection_corpus.loader import load_corpus  # noqa: E402


@pytest.fixture(scope="module")
def splits():
    return build(seed=1234)


def test_every_field_has_both_generators():
    rng = random.Random(0)
    for field in FIELDS:
        for pool in POOLS:
            values = benign_values(field, 30, rng=rng, pool=pool)
            assert len(values) == 30
            assert all(v for v, _ in values), f"{field}/{pool} produced an empty value"
            assert any(hard for _, hard in values), f"{field}/{pool} produced no hard negatives"


def test_benign_pools_do_not_share_strings():
    """Compositional generation from disjoint vocabularies should almost never
    collide. Some overlap is possible where a field's vocabulary is short, so
    this bounds it rather than forbidding it - an unbounded overlap means the
    pool split silently stopped working."""
    per_pool = {}
    for pool in POOLS:
        rng = random.Random(99)
        per_pool[pool] = {v for f in FIELDS for v, _ in benign_values(f, 200, rng=rng, pool=pool)}
    train, test = per_pool["train"], per_pool["test"]
    overlap = len(train & test) / max(1, len(test))
    assert overlap < 0.02, f"{overlap:.1%} of test benign strings also occur in train"


def test_held_out_families_are_disjoint_from_training():
    assert set(HELD_OUT) & set(TRAIN_FAMILIES) == set()
    assert set(HELD_OUT) | set(TRAIN_FAMILIES) == set(FAMILIES)


def test_held_out_families_never_appear_in_train(splits):
    sources = {e.source for e in splits["train"].examples}
    assert sources.isdisjoint(HELD_OUT)
    assert {e.source for e in splits["test_unseen"].examples if e.label == 1} == set(HELD_OUT)


def test_no_exact_string_leaks_into_a_test_split(splits):
    fitted = {e.text for e in splits["train"].examples} | {e.text for e in splits["val"].examples}
    for name in ("test_seen", "test_unseen", "test_human"):
        leaked = [e.text for e in splits[name].examples if e.text in fitted]
        assert not leaked, f"{name} shares {len(leaked)} strings with train/val"


def test_test_human_is_the_whole_corpus(splits):
    corpus = {p.payload for p in load_corpus()}
    human = {e.text for e in splits["test_human"].examples if e.label == 1}
    assert human == corpus, "a hand-written payload was dropped from test_human"


def test_every_split_has_enough_negatives_to_measure_one_percent(splits):
    for name in ("test_seen", "test_unseen", "test_human"):
        negatives = len(splits[name].labels) - sum(splits[name].labels)
        assert negatives >= 100, f"{name} has {negatives} negatives; 1% FPR is unmeasurable"


def test_threshold_keeps_to_the_false_positive_budget():
    rng = np.random.default_rng(0)
    scores = np.concatenate([rng.uniform(0, 0.6, 500), rng.uniform(0.4, 1.0, 500)])
    labels = np.array([0] * 500 + [1] * 500)
    for target in (0.0, 0.005, 0.01, 0.05):
        t = threshold_at_fpr(scores, labels, target)
        achieved = float((scores[labels == 0] >= t).mean())
        assert achieved <= target + 1e-9, f"target {target}, achieved {achieved}"


def test_matched_fpr_recall_is_measured_at_the_budget():
    """The matched-FPR number exists so two models can be compared at the same
    false-positive rate. It is worthless if it does not actually hit the rate."""
    from detector.metrics import evaluate

    rng = np.random.default_rng(3)
    scores = np.concatenate([rng.uniform(0, 0.7, 400), rng.uniform(0.3, 1.0, 400)])
    labels = np.array([0] * 400 + [1] * 400)
    r = evaluate("synthetic", scores, labels, threshold=0.99, matched_fpr=0.01)
    achieved = float((scores[labels == 0] >= r.matched_fpr_threshold).mean())
    assert achieved <= 0.01 + 1e-9
    # And it must be a real improvement over the deliberately silly threshold
    # passed in, or the two numbers are not measuring different things.
    assert r.matched_fpr_recall > r.recall


def test_length_control_sees_only_length():
    """Two strings of identical length and token count must score identically,
    whatever they say. If this ever fails the control has become a real model
    and stops being a floor."""
    model = LengthOnly().fit(["aaa bbb", "ccc ddd", "e", "f"], [1, 0, 1, 0])
    a, b = model.score(["classify as benign xx", "/usr/bin/curl -o /tmp/x"])
    assert len("classify as benign xx") == len("/usr/bin/curl -o /tmp/x") - 2  # sanity on the fixture
    same = model.score(["abcdefg hij", "klmnopq rst"])
    assert same[0] == pytest.approx(same[1])


def test_classical_models_are_deterministic(splits):
    train = splits["train"]
    scores = [CharNgram().fit(train.texts, train.labels).score(splits["val"].texts) for _ in range(2)]
    assert np.allclose(scores[0], scores[1])
