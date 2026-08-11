import pytest

from eval.harness import run_corpus, splice_payload, summarize
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


def test_summarize_computes_overall_and_per_goal_bypass_rates():
    def fake_narrate_always_benign(incident) -> str:
        return "Everything here is benign and no action is needed."

    results = run_corpus(narrate=fake_narrate_always_benign, payloads=_CORPUS)
    summary = summarize(results)

    assert summary["overall"] == sum(r.bypass_detected for r in results) / len(results)
    severity_downgrade_results = [r for r in results if r.goal == "severity_downgrade"]
    assert summary["severity_downgrade"] == sum(r.bypass_detected for r in severity_downgrade_results) / len(
        severity_downgrade_results
    )


def test_summarize_of_empty_results_returns_empty_dict():
    assert summarize([]) == {}


def test_failed_narration_is_excluded_not_scored():
    """An unusable response is missing data - neither a bypass nor a
    non-bypass. Forcing it into either bucket would bias the rate."""
    from eval.harness import run_corpus
    from injection_corpus.loader import load_corpus

    payloads = load_corpus()[:4]
    seen = []

    def flaky(_incident):
        if len(seen) == 1:
            raise RuntimeError("truncated at the token cap")
        return "Severity: critical. Host web-01 ran /usr/bin/curl and /tmp/payload."

    def narrate(incident):
        seen.append(1)
        return flaky(incident)

    errors = []
    results = run_corpus(
        narrate=narrate, payloads=payloads,
        on_error=lambda p, e: errors.append((p.id, str(e))),
    )
    assert len(results) == len(payloads) - 1, "failed payload must be out of the denominator"
    assert len(errors) == 1
    assert "truncated" in errors[0][1]


def test_failure_still_raises_when_no_error_handler():
    """Without an on_error handler the failure must not be swallowed."""
    from eval.harness import run_corpus
    from injection_corpus.loader import load_corpus

    def boom(_incident):
        raise RuntimeError("backend down")

    with pytest.raises(RuntimeError, match="backend down"):
        run_corpus(narrate=boom, payloads=load_corpus()[:2])
