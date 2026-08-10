import csv
import json

from eval.harness import RunResult
from eval.run_all import csv_safe, format_summary_table, write_csv, write_json

_FIXTURE_RESULTS = {
    "naive": [
        RunResult("pm-01", "process_metadata", "severity_downgrade", "output text", True, "benign language"),
        RunResult("fp-01", "file_path", "entity_omission", "output text", False, "entity present"),
    ],
    "hardened": [
        RunResult("pm-01", "process_metadata", "severity_downgrade", "Severity: high", False, "no downgrade"),
        RunResult("fp-01", "file_path", "entity_omission", "Entities: /tmp/x", False, "entity present"),
    ],
}


def test_write_csv_contains_one_row_per_result_across_all_tiers(tmp_path):
    path = tmp_path / "out.csv"
    write_csv(path, _FIXTURE_RESULTS)
    text = path.read_text()
    lines = text.strip().splitlines()
    assert lines[0] == "tier,payload_id,category,goal,bypass_detected,reason,narrator_output"
    assert len(lines) == 1 + sum(len(rs) for rs in _FIXTURE_RESULTS.values())
    assert any(line.startswith("naive,pm-01,") for line in lines)
    assert any(line.startswith("hardened,fp-01,") for line in lines)


def test_write_json_round_trips_results_and_summaries(tmp_path):
    path = tmp_path / "out.json"
    summaries = {"naive": {"overall": 0.5}, "hardened": {"overall": 0.0}}
    write_json(path, _FIXTURE_RESULTS, summaries, model="claude-opus-4-8", backend="anthropic")
    parsed = json.loads(path.read_text())

    assert parsed["model"] == "claude-opus-4-8"
    assert parsed["backend"] == "anthropic"
    assert parsed["summaries"] == summaries
    assert parsed["results"]["naive"][0]["payload_id"] == "pm-01"
    assert parsed["results"]["hardened"][1]["reason"] == "entity present"
    assert "generated_at" in parsed


def test_format_summary_table_includes_every_tier_and_goal_column():
    summaries = {
        "naive": {"overall": 0.9, "severity_downgrade": 0.8, "entity_omission": 1.0, "instruction_leak": 0.9},
        "hardened": {"overall": 0.2, "severity_downgrade": 0.1, "entity_omission": 0.2, "instruction_leak": 0.3},
        "structural": {"overall": 0.0, "severity_downgrade": 0.0, "entity_omission": 0.0, "instruction_leak": 0.0},
    }
    table = format_summary_table(summaries)
    assert "naive" in table
    assert "hardened" in table
    assert "structural" in table
    assert "severity_downgrade" in table
    assert "90%" in table  # naive overall


def test_format_summary_table_handles_missing_tier_summary_gracefully():
    # if a tier's run produced no results, summarize() returns {} for it -
    # the table must still render a row instead of raising a KeyError.
    table = format_summary_table({"naive": {"overall": 1.0}})
    assert "hardened" in table
    assert "structural" in table


# --- CSV formula injection: this export carries attacker-authored text ---


def test_csv_safe_neutralizes_every_formula_trigger():
    for trigger in ("=", "+", "-", "@", "\t", "\r"):
        payload = f"{trigger}cmd|' /C calc'!A0"
        assert csv_safe(payload).startswith("'" + trigger)


def test_csv_safe_leaves_ordinary_values_untouched():
    assert csv_safe("output never mentions /tmp/payload") == "output never mentions /tmp/payload"
    assert csv_safe(True) is True
    assert csv_safe(0.5) == 0.5


def test_write_csv_neutralizes_a_formula_in_attacker_controlled_columns(tmp_path):
    hostile = RunResult(
        payload_id="=HYPERLINK(\"http://evil\",\"click\")",
        category="file_path",
        goal="entity_omission",
        narrator_output="@SUM(1+1)*cmd|' /C calc'!A0",
        bypass_detected=True,
        reason="-2+3+cmd|' /C calc'!A0",
    )
    path = tmp_path / "out.csv"
    write_csv(path, {"naive": [hostile]})

    # csv.reader gives back the literal cell text, quoting stripped
    rows = list(csv.reader(path.read_text().splitlines()))
    body = rows[1]
    for cell in body:
        assert not cell.startswith(("=", "+", "-", "@", "\t", "\r")), f"live formula survived: {cell!r}"
