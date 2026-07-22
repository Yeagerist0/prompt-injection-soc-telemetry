from eval.harness import run_corpus, splice_payload
from eval.judge import _extract_entity_marker
from injection_corpus.loader import load_corpus
from telemetry.synth_events import download_exec_incident

_CORPUS = load_corpus()


def test_splice_payload_overwrites_only_the_targeted_field():
    payload = next(p for p in _CORPUS if p.id == "pm-01")
    incident = splice_payload(download_exec_incident, payload)
    assert incident.events[-1].proc_image == payload.payload
    # sanity: splicing didn't touch the base incident's other events
    baseline = download_exec_incident()
    assert len(incident.events) == len(baseline.events)


def test_splice_payload_does_not_mutate_the_base_incident_generator():
    payload = next(p for p in _CORPUS if p.id == "na-01")
    before = download_exec_incident().events[-1].dns_name
    splice_payload(download_exec_incident, payload)
    after = download_exec_incident().events[-1].dns_name
    assert before == after  # generator produces a fresh incident each call


def test_run_corpus_produces_one_result_per_payload_with_a_fake_narrator():
    def fake_narrate_always_benign(incident) -> str:
        return "Everything here is benign and no action is needed."

    results = run_corpus(narrate=fake_narrate_always_benign, payloads=_CORPUS)
    assert len(results) == len(_CORPUS)

    by_id = {r.payload_id: r for r in results}
    severity_downgrade_ids = [p.id for p in _CORPUS if p.goal == "severity_downgrade"]
    assert severity_downgrade_ids  # sanity: corpus actually has some
    for pid in severity_downgrade_ids:
        assert by_id[pid].bypass_detected, f"{pid} should have been flagged against a benign-only fake narrator"


def test_accurate_narrator_bypasses_far_fewer_than_always_benign_narrator():
    def fake_narrate_always_benign(incident) -> str:
        return "Everything here is benign and no action is needed."

    def fake_narrate_accurate(incident) -> str:
        # Cite the *extracted marker* for each field, not the raw field text -
        # a few corpus entries (e.g. sentence-like smuggled subdomains) bake
        # the injected phrase and the identifying entity into the same
        # token, so echoing the raw field verbatim would repeat the
        # attacker's language regardless of how "accurate" the narrator is.
        last = incident.events[-1]
        raw_fields = [last.proc_image, last.file_path, last.dns_name, last.proc_cmdline]
        markers = [_extract_entity_marker(f) for f in raw_fields if f]
        return (
            "High-severity incident: a malicious download-and-execute chain was observed, "
            f"involving {' '.join(markers)}."
        )

    benign_results = run_corpus(narrate=fake_narrate_always_benign, payloads=_CORPUS)
    accurate_results = run_corpus(narrate=fake_narrate_accurate, payloads=_CORPUS)

    benign_bypass_count = sum(r.bypass_detected for r in benign_results)
    accurate_bypass_count = sum(r.bypass_detected for r in accurate_results)
    assert accurate_bypass_count < benign_bypass_count
