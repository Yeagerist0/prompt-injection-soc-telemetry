from injection_corpus.loader import by_category, load_corpus


def test_corpus_loads_and_has_at_least_30_payloads():
    payloads = load_corpus()
    assert len(payloads) >= 30


def test_all_four_categories_present_and_roughly_balanced():
    payloads = load_corpus()
    grouped = by_category(payloads)
    assert set(grouped) == {"process_metadata", "file_path", "network_artifact", "log_string"}
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
    }
    for p in load_corpus():
        assert p.field == expected[p.category]
