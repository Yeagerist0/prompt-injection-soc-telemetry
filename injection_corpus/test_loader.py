from injection_corpus.loader import by_category, load_corpus


def test_corpus_loads_and_has_at_least_30_payloads():
    payloads = load_corpus()
    assert len(payloads) >= 30


def test_all_categories_present_and_roughly_balanced():
    payloads = load_corpus()
    grouped = by_category(payloads)
    assert set(grouped) == {
        "process_metadata",
        "file_path",
        "network_artifact",
        "log_string",
        "registry_artifact",
        "http_artifact",
    }
    for cat, items in grouped.items():
        assert len(items) >= 5, f"{cat} has too few payloads ({len(items)})"


def test_payload_ids_are_unique():
    payloads = load_corpus()
    ids = [p.id for p in payloads]
    assert len(ids) == len(set(ids))


def test_every_payload_has_nonempty_text_and_valid_goal():
    valid_goals = {"severity_downgrade", "entity_omission", "instruction_leak"}
    for p in load_corpus():
        assert p.payload.strip()
        assert p.technique.strip()
        assert p.goal in valid_goals


def test_field_matches_category_mapping():
    expected = {
        "process_metadata": "proc_image",
        "file_path": "file_path",
        "network_artifact": "dns_name",
        "log_string": "proc_cmdline",
        "registry_artifact": "registry_key",
        "http_artifact": "user_agent",
    }
    for p in load_corpus():
        assert p.field == expected[p.category]


def test_tier_target_defaults_to_generic_and_only_uses_known_values():
    payloads = load_corpus()
    assert all(p.tier_target in {"generic", "hardened", "structural"} for p in payloads)
    # the corpus must actually exercise the tier-targeted classes, otherwise
    # the eval only ever measures generic prose attacks
    targets = {p.tier_target for p in payloads}
    assert {"hardened", "structural"} <= targets


def test_corpus_includes_invisible_character_evasion_payloads():
    # zero-width and bidi-override payloads are the ones most likely to be
    # silently normalized away by a careless edit to the YAML, so pin them.
    payloads = {p.id: p for p in load_corpus()}
    assert "​" in payloads["ua-06"].payload
    assert "‮" in payloads["ua-07"].payload
    assert "​" in payloads["adv-03"].payload
