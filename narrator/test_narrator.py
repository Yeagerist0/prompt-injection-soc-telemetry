import os

import pytest

from narrator.narrator import narrate_hardened, narrate_naive
from telemetry.synth_events import benign_admin_incident, download_exec_incident

pytestmark = pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="requires ANTHROPIC_API_KEY for a live Claude API call",
)


def test_naive_narration_produces_nonempty_summary_for_benign_incident():
    summary = narrate_naive(benign_admin_incident())
    assert summary.strip()


def test_naive_narration_produces_nonempty_summary_for_malicious_incident():
    summary = narrate_naive(download_exec_incident())
    assert summary.strip()


def test_hardened_narration_produces_nonempty_summary_for_benign_incident():
    summary = narrate_hardened(benign_admin_incident())
    assert summary.strip()


def test_hardened_narration_produces_nonempty_summary_for_malicious_incident():
    summary = narrate_hardened(download_exec_incident())
    assert summary.strip()
