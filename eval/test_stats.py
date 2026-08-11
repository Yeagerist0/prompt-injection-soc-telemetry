from __future__ import annotations

import pytest

from eval.stats import aligned_flags, bootstrap_paired_difference, bootstrap_rate


def test_rate_point_estimate_matches_mean():
    flags = [True] * 15 + [False] * 51
    result = bootstrap_rate(flags, resamples=2000, seed=1)
    assert result.point == pytest.approx(15 / 66)
    assert result.lo < result.point < result.hi


def test_rate_interval_is_degenerate_when_no_variation():
    result = bootstrap_rate([False] * 66, resamples=500, seed=1)
    assert (result.point, result.lo, result.hi) == (0.0, 0.0, 0.0)


def test_smaller_sample_gives_wider_interval():
    """The interval has to respond to sample size, or it isn't measuring
    anything about the corpus."""
    small = bootstrap_rate([True] * 3 + [False] * 7, resamples=4000, seed=2)
    large = bootstrap_rate([True] * 30 + [False] * 70, resamples=4000, seed=2)
    assert (small.hi - small.lo) > (large.hi - large.lo)


def test_paired_difference_detects_a_real_gap():
    a = [True] * 40 + [False] * 26
    b = [False] * 66
    result = bootstrap_paired_difference(a, b, resamples=4000, seed=3)
    assert result.point == pytest.approx(40 / 66)
    assert result.lo > 0  # excludes zero: the tiers really differ


def test_paired_difference_spans_zero_when_tiers_disagree_both_ways():
    """Close rates only produce a two-sided interval if the tiers actually
    fail on *different* payloads."""
    a = [True] * 5 + [False] * 4 + [False] * 57
    b = [False] * 5 + [True] * 4 + [False] * 57
    result = bootstrap_paired_difference(a, b, resamples=4000, seed=4)
    assert result.lo < 0 < result.hi
    assert not result.excludes_zero


def test_nested_failures_give_a_one_sided_interval():
    """When one tier's bypasses are a strict superset of the other's, no
    resample can flip the sign - the pairing makes that structurally
    impossible, and the interval should say so rather than straddle zero."""
    a = [True] * 5 + [False] * 61
    b = [True] * 4 + [False] * 62  # exactly a's failures, minus one
    result = bootstrap_paired_difference(a, b, resamples=4000, seed=4)
    assert result.lo == 0.0
    assert result.hi > 0


def test_pairing_is_preserved_and_narrows_the_interval():
    """Identical tiers have exactly zero difference on every resample; treating
    them as independent would produce a spurious spread."""
    flags = [True, False] * 33
    result = bootstrap_paired_difference(flags, flags, resamples=1000, seed=5)
    assert (result.point, result.lo, result.hi) == (0.0, 0.0, 0.0)


def test_paired_difference_rejects_mismatched_lengths():
    with pytest.raises(ValueError, match="equal-length"):
        bootstrap_paired_difference([True, False], [True], resamples=10)


def test_aligned_flags_orders_by_shared_payload_ids():
    results = {
        "naive": [
            {"payload_id": "b", "bypass_detected": True},
            {"payload_id": "a", "bypass_detected": False},
            {"payload_id": "z", "bypass_detected": True},
        ],
        "hardened": [
            {"payload_id": "a", "bypass_detected": True},
            {"payload_id": "b", "bypass_detected": False},
        ],
    }
    a, b = aligned_flags(results, "naive", "hardened")
    assert (a, b) == ([False, True], [True, False])  # ordered a, b; 'z' dropped
