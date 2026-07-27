import json

from eval.dashboard import build_lookup, find_latest_results, render_page
from eval.harness import TIERS
from injection_corpus.loader import load_corpus

_PAYLOADS = load_corpus()


def _synthetic_run() -> dict:
    return {
        "model": "claude-opus-4-8",
        "generated_at": "2026-07-22T12:00:00+00:00",
        "summaries": {
            "naive": {"overall": 0.82, "severity_downgrade": 0.9},
            "hardened": {"overall": 0.25, "severity_downgrade": 0.2},
            "structural": {"overall": 0.05, "severity_downgrade": 0.0},
        },
        "results": {
            tier: [{"payload_id": p.id, "bypass_detected": i % 2 == 0} for i, p in enumerate(_PAYLOADS)]
            for tier in TIERS
        },
    }


# --- the honesty-critical behaviour: no run must never render a number ---


def test_no_run_marks_every_cell_not_measured_and_invents_no_numbers():
    page = render_page(_PAYLOADS, run=None)
    assert page.count('title="not measured"') == len(_PAYLOADS) * len(TIERS)
    assert 'title="bypass detected"' not in page
    assert 'title="defense held"' not in page
    # no percentage figure anywhere in the tier readouts
    assert "pi-tier-pct is-pending" in page
    assert "%<" not in page.split("pi-legend")[0].replace('style="width', "")


def test_no_run_still_renders_the_real_corpus_content():
    page = render_page(_PAYLOADS, run=None)
    for p in _PAYLOADS:
        assert p.id in page
    assert "Event.proc_image" in page
    assert "Event.proc_cmdline" in page
    assert "python -m eval.run_all" in page


def test_no_run_banner_states_it_has_not_been_run():
    page = render_page(_PAYLOADS, run=None)
    assert "Not run" in page
    assert "no evaluation has been run against the live API yet" in page
    assert "pi-status is-live" not in page


# --- populated path ---


def test_populated_run_renders_one_result_cell_per_payload_per_tier():
    page = render_page(_PAYLOADS, run=_synthetic_run())
    bypass = page.count('title="bypass detected"')
    held = page.count('title="defense held"')
    assert bypass + held == len(_PAYLOADS) * len(TIERS)
    assert 'title="not measured"' not in page


def test_populated_run_shows_tier_percentages_and_model():
    page = render_page(_PAYLOADS, run=_synthetic_run())
    assert "82%" in page
    assert "25%" in page
    assert "claude-opus-4-8" in page
    assert "pi-status is-live" in page


def test_build_lookup_maps_tier_and_payload_to_bypass_flag():
    lookup = build_lookup(_synthetic_run())
    assert len(lookup) == len(_PAYLOADS) * len(TIERS)
    assert lookup[("naive", _PAYLOADS[0].id)] is True
    assert lookup[("naive", _PAYLOADS[1].id)] is False


def test_build_lookup_of_none_is_empty():
    assert build_lookup(None) == {}


# --- output plumbing ---


def test_body_only_omits_the_document_wrapper():
    fragment = render_page(_PAYLOADS, run=None, body_only=True)
    assert "<!doctype" not in fragment.lower()
    assert "<html" not in fragment.lower()
    assert "<style>" in fragment
    assert "pi-root" in fragment


def test_full_page_is_self_contained_with_no_external_requests():
    page = render_page(_PAYLOADS, run=_synthetic_run())
    assert page.lower().startswith("<!doctype html>")
    assert "http://" not in page
    assert "https://" not in page


def test_page_defines_both_theme_token_sets():
    page = render_page(_PAYLOADS, run=None)
    assert "prefers-color-scheme: dark" in page
    assert ':root[data-theme="dark"]' in page
    assert ':root[data-theme="light"]' in page


def test_find_latest_results_picks_the_newest_run_and_handles_empty(tmp_path):
    assert find_latest_results(tmp_path) is None
    (tmp_path / "run_20260101T000000Z.json").write_text("{}")
    (tmp_path / "run_20260722T120000Z.json").write_text(json.dumps(_synthetic_run()))
    assert find_latest_results(tmp_path).name == "run_20260722T120000Z.json"
