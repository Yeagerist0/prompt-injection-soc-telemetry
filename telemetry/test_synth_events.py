from telemetry.schema import Event, EventType, Incident
from telemetry.synth_events import (
    ALL_INCIDENTS,
    benign_admin_incident,
    credential_theft_incident,
    download_exec_incident,
)


def test_all_incidents_produce_nonempty_events():
    for name, fn in ALL_INCIDENTS.items():
        inc = fn()
        assert inc.events, f"{name} produced no events"
        assert inc.host_id
        assert 0 <= inc.risk_score <= 100


def test_benign_incident_is_low_risk_no_techniques():
    inc = benign_admin_incident()
    assert inc.risk_score < 20
    assert inc.technique_set == []


def test_malicious_incidents_are_high_risk_with_techniques():
    for fn in (download_exec_incident, credential_theft_incident):
        inc = fn()
        assert inc.risk_score >= 80
        assert inc.technique_set


def test_raw_log_contains_every_event_line():
    inc = download_exec_incident()
    log = inc.raw_log()
    for e in inc.events:
        assert e.as_line() in log


def test_event_as_line_includes_attacker_controlled_fields_unescaped():
    # This is the vulnerability surface, made explicit: as_line() does no
    # escaping or delimiting of attacker-controlled fields. If it ever starts
    # sanitizing here, the naive-narrator baseline stops being naive.
    e = Event(id="e1", ts="2026-01-01T00:00:00", type=EventType.PROCESS_START,
              host_id="h", proc_guid="g", proc_image='evil"; rm -rf /')
    assert 'evil"; rm -rf /' in e.as_line()


def test_incident_ids_are_distinct_across_generators():
    ids = {fn().id for fn in ALL_INCIDENTS.values()}
    assert len(ids) == len(ALL_INCIDENTS)
