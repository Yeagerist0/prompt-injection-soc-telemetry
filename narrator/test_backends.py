"""Tests for backend selection and the OpenAI-compatible shim.

None of these make a network call. The shim's HTTP layer is stubbed so the
translation logic - Anthropic-shaped kwargs in, chat-completions body out -
is tested on its own.
"""
from __future__ import annotations

import json

import pytest

from narrator import backends
from narrator.backends import (
    BackendError,
    OpenAICompatClient,
    TextBlock,
    describe_backend,
    extract_json,
    get_client,
)

SCHEMA = {"type": "object", "properties": {"severity": {"type": "string"}}}


@pytest.fixture(autouse=True)
def clear_backend_env(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("NARRATOR_API_KEY", raising=False)
    monkeypatch.delenv("NARRATOR_BASE_URL", raising=False)


class RecordingTransport:
    """Stands in for _post_json, recording bodies and replaying scripted results."""

    def __init__(self, results):
        self.results = list(results)
        self.bodies = []

    def __call__(self, url, headers, body):
        self.bodies.append(body)
        outcome = self.results.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return {"choices": [{"message": {"content": outcome}}]}


def make_client(monkeypatch, results):
    transport = RecordingTransport(results)
    monkeypatch.setattr(backends, "_post_json", transport)
    client = OpenAICompatClient(api_key="k", base_url="https://example.test/v1")
    return client, transport


# --- extract_json -----------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ('{"severity":"high"}', '{"severity":"high"}'),
        ('```json\n{"severity":"high"}\n```', '{"severity":"high"}'),
        ('Sure! Here you go:\n{"severity":"high"}\nHope that helps.', '{"severity":"high"}'),
        ('  \n {"severity":"high"} \n', '{"severity":"high"}'),
    ],
)
def test_extract_json_recovers_object(raw, expected):
    assert json.loads(extract_json(raw)) == json.loads(expected)


def test_extract_json_passes_through_when_no_object():
    assert extract_json("no json here") == "no json here"


# --- request translation ----------------------------------------------------


def test_system_prompt_becomes_system_message(monkeypatch):
    client, transport = make_client(monkeypatch, ["plain text"])
    client.messages.create(
        model="m", max_tokens=64, system="SYS", messages=[{"role": "user", "content": "U"}]
    )
    assert transport.bodies[0]["messages"] == [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "U"},
    ]


def test_response_is_anthropic_shaped(monkeypatch):
    client, _ = make_client(monkeypatch, ["hello"])
    response = client.messages.create(
        model="m", max_tokens=64, messages=[{"role": "user", "content": "U"}]
    )
    assert [b.type for b in response.content] == ["text"]
    assert "".join(b.text for b in response.content if b.type == "text") == "hello"
    assert response.content == [TextBlock(text="hello")]


def test_output_config_becomes_strict_json_schema(monkeypatch):
    client, transport = make_client(monkeypatch, ['{"severity":"high"}'])
    client.messages.create(
        model="m",
        max_tokens=64,
        messages=[{"role": "user", "content": "U"}],
        output_config={"format": {"type": "json_schema", "schema": SCHEMA}},
    )
    response_format = transport.bodies[0]["response_format"]
    assert response_format["type"] == "json_schema"
    assert response_format["json_schema"]["strict"] is True
    assert response_format["json_schema"]["schema"] == SCHEMA


def test_temperature_is_pinned_to_zero(monkeypatch):
    """Bypass rates that move because of sampling noise aren't measurements."""
    client, transport = make_client(monkeypatch, ["x"])
    client.messages.create(model="m", max_tokens=64, messages=[{"role": "user", "content": "U"}])
    assert transport.bodies[0]["temperature"] == 0


# --- structured-output fallback chain ---------------------------------------


def test_falls_back_through_schema_modes(monkeypatch):
    """A provider that rejects strict json_schema should still get measured,
    with the schema moved into the prompt instead."""
    client, transport = make_client(
        monkeypatch,
        [
            BackendError("HTTP 400: strict unsupported"),
            BackendError("HTTP 400: json_schema unsupported"),
            '{"severity":"high"}',
        ],
    )
    response = client.messages.create(
        model="m",
        max_tokens=64,
        system="SYS",
        messages=[{"role": "user", "content": "U"}],
        output_config={"format": {"type": "json_schema", "schema": SCHEMA}},
    )
    assert json.loads(response.content[0].text) == {"severity": "high"}
    assert [b.get("response_format", {}).get("type") for b in transport.bodies] == [
        "json_schema",
        "json_schema",
        "json_object",
    ]
    # the json_object attempt must carry the schema in the system message
    assert "JSON Schema" in transport.bodies[2]["messages"][0]["content"]
    assert transport.bodies[2]["messages"][0]["content"].startswith("SYS")


def test_raises_when_every_mode_rejected(monkeypatch):
    client, _ = make_client(monkeypatch, [BackendError("HTTP 400")] * 4)
    with pytest.raises(BackendError, match="every structured-output mode"):
        client.messages.create(
            model="m",
            max_tokens=64,
            messages=[{"role": "user", "content": "U"}],
            output_config={"format": {"type": "json_schema", "schema": SCHEMA}},
        )


# --- selection --------------------------------------------------------------


def test_get_client_prefers_narrator_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    monkeypatch.setenv("NARRATOR_API_KEY", "k")
    monkeypatch.setenv("NARRATOR_BASE_URL", "https://example.test/v1")
    assert isinstance(get_client(), OpenAICompatClient)


def test_get_client_requires_base_url(monkeypatch):
    monkeypatch.setenv("NARRATOR_API_KEY", "k")
    with pytest.raises(BackendError, match="NARRATOR_BASE_URL"):
        get_client()


def test_get_client_errors_with_no_backend():
    with pytest.raises(BackendError, match="no model backend configured"):
        get_client()


def test_describe_backend_reports_selection(monkeypatch):
    assert describe_backend() == "none"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    assert describe_backend() == "anthropic"
    monkeypatch.setenv("NARRATOR_API_KEY", "k")
    monkeypatch.setenv("NARRATOR_BASE_URL", "https://example.test/v1")
    assert describe_backend() == "openai-compat:https://example.test/v1"


def test_empty_completion_raises_rather_than_scoring(monkeypatch):
    """An empty narration names no entities and states no severity, which the
    judge scores as a successful bypass. It must fail instead."""
    client, _ = make_client(monkeypatch, ["   "])
    with pytest.raises(BackendError, match="empty completion"):
        client.messages.create(model="m", max_tokens=64, messages=[{"role": "user", "content": "U"}])


def test_single_attempt_failure_is_not_blamed_on_schema_modes(monkeypatch):
    """A model-not-found error on a no-schema call shouldn't be reported as a
    structured-output problem."""
    client, _ = make_client(monkeypatch, [BackendError("HTTP 404: no such model")])
    with pytest.raises(BackendError, match="request to .* failed"):
        client.messages.create(model="m", max_tokens=64, messages=[{"role": "user", "content": "U"}])


def test_truncated_completion_raises_rather_than_scoring(monkeypatch):
    """A completion cut off at the token cap is partial data. On the prose
    tier it would be scored silently, and a narration that stops early names
    fewer entities - which the judge reads as an entity_omission bypass."""
    transport = RecordingTransport([None])
    def truncated(url, headers, body):
        return {"choices": [{"message": {"content": "The host web-01 ran /usr/bin/cur"},
                             "finish_reason": "length"}]}
    monkeypatch.setattr(backends, "_post_json", truncated)
    client = OpenAICompatClient(api_key="k", base_url="https://example.test/v1")
    with pytest.raises(BackendError, match="truncated at the token cap"):
        client.messages.create(model="m", max_tokens=8, messages=[{"role": "user", "content": "U"}])


def test_complete_completion_is_returned(monkeypatch):
    """finish_reason=stop must still pass through untouched."""
    def complete(url, headers, body):
        return {"choices": [{"message": {"content": "done."}, "finish_reason": "stop"}]}
    monkeypatch.setattr(backends, "_post_json", complete)
    client = OpenAICompatClient(api_key="k", base_url="https://example.test/v1")
    r = client.messages.create(model="m", max_tokens=64, messages=[{"role": "user", "content": "U"}])
    assert r.content[0].text == "done."


def test_rate_limit_backoff_is_much_longer_than_a_transient_error():
    """A 429 needs the quota window to elapse. Backing off on the same
    one-second-exponential schedule as a 503 gives up after about a minute and
    leaves the run with excluded payloads, which silently changes the
    denominator of every rate the run reports."""
    import urllib.error

    from narrator.backends import _retry_delay

    class E(urllib.error.HTTPError):
        def __init__(self, code, headers=None):
            self.code = code
            self.headers = headers or {}

    for attempt in range(4):
        assert _retry_delay(E(429), attempt) > _retry_delay(E(503), attempt)
    assert _retry_delay(E(429), 0) >= 30
    assert _retry_delay(E(429), 9) <= 300


def test_retry_after_header_wins_when_the_server_sends_one():
    import urllib.error

    from narrator.backends import _retry_delay

    class E(urllib.error.HTTPError):
        def __init__(self, code, headers):
            self.code = code
            self.headers = headers

    assert _retry_delay(E(429, {"Retry-After": "12"}), 3) == 13.0
    # A malformed header must fall back rather than raise mid-run.
    assert _retry_delay(E(429, {"Retry-After": "soon"}), 0) >= 30
