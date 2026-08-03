import json

from eval.dashboard import build_lookup, find_latest_results, render_page, safe_json_for_script
from eval.harness import TIERS
from injection_corpus.loader import Payload, load_corpus

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
            tier: [
                {
                    "payload_id": p.id,
                    "bypass_detected": i % 2 == 0,
                    "reason": "fixture reason",
                    "narrator_output": "fixture output",
                }
                for i, p in enumerate(_PAYLOADS)
            ]
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


def test_build_lookup_maps_tier_and_payload_to_its_result_row():
    lookup = build_lookup(_synthetic_run())
    assert len(lookup) == len(_PAYLOADS) * len(TIERS)
    assert lookup[("naive", _PAYLOADS[0].id)]["bypass_detected"] is True
    assert lookup[("naive", _PAYLOADS[1].id)]["bypass_detected"] is False
    assert lookup[("naive", _PAYLOADS[0].id)]["narrator_output"] == "fixture output"


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
    # Note: bare http:// strings DO legitimately appear inside payload text
    # (several payloads are curl command lines), so the property to assert is
    # that nothing *fetches* an external resource - not that the substring is
    # absent.
    page = render_page(_PAYLOADS, run=_synthetic_run())
    assert page.lower().startswith("<!doctype html>")
    for sink in ('src="http', "src='http", 'href="http', "href='http", "url(http", "@import"):
        assert sink not in page, f"external resource reference: {sink}"


def test_page_defines_both_theme_token_sets():
    page = render_page(_PAYLOADS, run=None)
    assert "prefers-color-scheme: dark" in page
    assert ':root[data-theme="dark"]' in page
    assert ':root[data-theme="light"]' in page


# --- the page renders attacker-authored text; it must not be injectable ---


def test_safe_json_escapes_script_terminator():
    # JSON quoting alone does not protect inside a <script> block: the HTML
    # parser looks for a literal </script> regardless of JSON syntax.
    blob = safe_json_for_script({"payload": "</script><img src=x onerror=alert(1)>"})
    assert "</script>" not in blob
    assert "\\u003c" in blob
    assert json.loads(blob.replace("\\u003c", "<"))["payload"].startswith("</script>")


def _script_tag_count(page: str) -> tuple[int, int]:
    return page.count("<script"), page.count("</script>")


def test_hostile_payload_text_cannot_terminate_the_json_data_block():
    hostile = Payload(
        id="xss-01",
        category="file_path",
        field="file_path",
        technique="</script><script>alert(1)</script>",
        payload="</script><img src=x onerror=alert(1)>",
        goal="instruction_leak",
    )
    page = render_page([hostile], run=None)
    # Only the two script tags the template emits: the JSON data block and
    # the behaviour script. The payload's own </script> must not create more.
    assert _script_tag_count(page) == (2, 2)
    # every < that came from payload data is a \u003c escape, so no tag forms
    assert "<img" not in page
    assert "\\u003c/script>\\u003cimg" in page


def test_hostile_id_and_technique_are_html_escaped_in_the_table():
    hostile = Payload(
        id='xss-02"><img src=x onerror=alert(1)>',
        category="log_string",
        field="proc_cmdline",
        technique='<img src=x onerror="alert(1)">',
        payload="<svg onload=alert(1)>",
        goal="severity_downgrade",
    )
    page = render_page([hostile], run=None)
    assert "<img src=x" not in page
    assert "<svg onload" not in page
    assert "&lt;img src=x" in page  # technique, rendered into a table cell
    # payload text never reaches an HTML position at all - it is only handed
    # to the client as escaped JSON and inserted with textContent
    assert "\\u003csvg onload" in page


def test_hostile_narrator_output_from_a_run_cannot_inject_markup():
    run = {
        "model": "m",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "summaries": {},
        "results": {
            "naive": [
                {
                    "payload_id": _PAYLOADS[0].id,
                    "bypass_detected": True,
                    "reason": "</script><script>alert('reason')</script>",
                    "narrator_output": "</script><script>alert('output')</script>",
                }
            ]
        },
    }
    page = render_page(_PAYLOADS, run=run)
    assert _script_tag_count(page) == (2, 2)
    assert "\\u003c/script>\\u003cscript>alert('output')" in page


def test_find_latest_results_picks_the_newest_run_and_handles_empty(tmp_path):
    assert find_latest_results(tmp_path) is None
    (tmp_path / "run_20260101T000000Z.json").write_text("{}")
    (tmp_path / "run_20260722T120000Z.json").write_text(json.dumps(_synthetic_run()))
    assert find_latest_results(tmp_path).name == "run_20260722T120000Z.json"
