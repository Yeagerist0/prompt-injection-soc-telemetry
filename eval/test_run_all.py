import json

from eval.harness import RunResult
from eval.run_all import format_summary_table, write_csv, write_json

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
    assert lines[0] == "tier,payload_id,category,goal,bypass_detected,reason"
    assert len(lines) == 1 + sum(len(rs) for rs in _FIXTURE_RESULTS.values())
    assert any(line.startswith("naive,pm-01,") for line in lines)
    assert any(line.startswith("hardened,fp-01,") for line in lines)


def test_write_json_round_trips_results_and_summaries(tmp_path):
    path = tmp_path / "out.json"
    summaries = {"naive": {"overall": 0.5}, "hardened": {"overall": 0.0}}
    write_json(path, _FIXTURE_RESULTS, summaries, model="claude-opus-4-8")
    parsed = json.loads(path.read_text())

    assert parsed["model"] == "claude-opus-4-8"
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
