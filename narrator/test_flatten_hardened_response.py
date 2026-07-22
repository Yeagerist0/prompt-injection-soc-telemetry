from narrator.narrator import flatten_hardened_response


def test_flatten_renders_all_three_fields():
    flat = flatten_hardened_response(
        {"severity": "high", "entities": ["/tmp/payload", "c2.example-bad.net"], "summary": "Malware executed."}
    )
    assert "Severity: high" in flat
    assert "Entities: /tmp/payload, c2.example-bad.net" in flat
    assert "Summary: Malware executed." in flat


def test_flatten_handles_empty_entities_list():
    flat = flatten_hardened_response({"severity": "low", "entities": [], "summary": "Nothing happened."})
    assert "Entities: none" in flat


def test_flatten_falls_back_gracefully_on_missing_keys():
    flat = flatten_hardened_response({})
    assert "Severity: unknown" in flat
    assert "Entities: none" in flat
    assert "Summary: " in flat
