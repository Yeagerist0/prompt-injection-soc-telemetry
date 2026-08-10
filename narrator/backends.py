"""Model backend selection for the narrator tiers.

The three narrator tiers were written against the Anthropic SDK, but nothing
about the experiment is Anthropic-specific: the question is whether prompt-level
defenses survive attacker-controlled telemetry, and that question is worth
answering on whatever model you can actually get an API key for.

This module lets the same corpus run against any OpenAI-compatible chat
endpoint (Gemini's compat layer, Groq, OpenRouter, vLLM, llama.cpp's server)
by returning a shim that presents the small slice of the Anthropic client
surface the narrators use:

    client.messages.create(model=, max_tokens=, messages=, system=, output_config=)
        -> object with .content = [block(.type == "text", .text)]

Selection is by environment, so no call site changes:

    ANTHROPIC_API_KEY=sk-...                     -> real Anthropic SDK
    NARRATOR_API_KEY=... NARRATOR_BASE_URL=...   -> OpenAI-compatible shim

Whichever backend ran is recorded in the results file, because a bypass rate
without a model name attached is not a measurement.
"""
from __future__ import annotations

import json
import os
import re
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

# Free tiers rate-limit aggressively (Gemini's free tier is single-digit
# requests/minute on some models). A 198-call run that dies at call 40 with a
# 429 is a wasted run, so pace and retry rather than sprint and fail.
DEFAULT_RPM = int(os.environ.get("NARRATOR_RPM", "0"))
MAX_RETRIES = int(os.environ.get("NARRATOR_MAX_RETRIES", "6"))
TIMEOUT_S = float(os.environ.get("NARRATOR_TIMEOUT", "120"))


@dataclass(frozen=True)
class TextBlock:
    """Mirrors an Anthropic content block closely enough for the narrators,
    which only ever read `.type` and `.text`."""

    text: str
    type: str = "text"


@dataclass(frozen=True)
class Response:
    content: list[TextBlock] = field(default_factory=list)


class BackendError(RuntimeError):
    """Raised when a backend fails in a way retrying will not fix."""


class _Throttle:
    """Spaces requests to at most `rpm` per minute across threads."""

    def __init__(self, rpm: int) -> None:
        self._min_interval = 60.0 / rpm if rpm > 0 else 0.0
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = max(0.0, self._next_allowed - now)
            self._next_allowed = max(now, self._next_allowed) + self._min_interval
        if sleep_for:
            time.sleep(sleep_for)


def extract_json(text: str) -> str:
    """Pull a JSON object out of a model response.

    Providers that don't honour a strict schema still tend to return the right
    JSON wrapped in prose or a ```json fence. Falling back to a brace scan
    keeps a provider's chattiness from being scored as a defense failure -
    which would silently inflate the bypass rate of whichever tier asks for
    structured output.
    """
    stripped = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", stripped, re.DOTALL)
    if fence:
        stripped = fence.group(1).strip()
    if stripped.startswith("{"):
        return stripped
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end > start:
        return stripped[start : end + 1]
    return stripped


def _schema_of(output_config: dict[str, Any] | None) -> dict[str, Any] | None:
    if not output_config:
        return None
    return (output_config.get("format") or {}).get("schema")


@contextmanager
def _hard_deadline(seconds: float):
    """Enforce a total wall-clock deadline on a request.

    urllib's `timeout` applies per socket operation, not to the request as a
    whole, so a connection that stalls mid-body can hang forever. A hung run
    is worse than a failed one: it produces silence, and silence is
    indistinguishable from slow progress. SIGALRM gives a hard ceiling.

    Only arms in the main thread of a platform that has SIGALRM; elsewhere it
    is a no-op and the per-socket timeout is the only guard.
    """
    if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
        yield
        return

    def _fire(_signum, _frame):
        raise TimeoutError(f"request exceeded {seconds:.0f}s hard deadline")

    previous = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _post_json(url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
        return json.loads(response.read().decode())


class _OpenAICompatMessages:
    def __init__(self, client: "OpenAICompatClient") -> None:
        self._client = client

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: list[dict[str, Any]],
        system: str | None = None,
        output_config: dict[str, Any] | None = None,
    ) -> Response:
        schema = _schema_of(output_config)
        chat_messages: list[dict[str, Any]] = []
        if system:
            chat_messages.append({"role": "system", "content": system})
        chat_messages.extend({"role": m["role"], "content": m["content"]} for m in messages)

        # Try the strictest structured-output mode the provider might support,
        # then degrade. Each fallback puts the schema in the prompt instead, so
        # the model is still told exactly what shape to return.
        attempts: list[dict[str, Any] | None] = [None]
        if schema is not None:
            attempts = [
                {"type": "json_schema", "json_schema": {"name": "response", "schema": schema, "strict": True}},
                {"type": "json_schema", "json_schema": {"name": "response", "schema": schema}},
                {"type": "json_object"},
                None,
            ]

        last_error: Exception | None = None
        attempted_schema_modes = 0
        for response_format in attempts:
            attempted_schema_modes += 1
            payload_messages = chat_messages
            if schema is not None and (response_format is None or response_format["type"] == "json_object"):
                payload_messages = self._with_schema_instruction(chat_messages, schema)
            body: dict[str, Any] = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": payload_messages,
                "temperature": 0,
            }
            if response_format is not None:
                body["response_format"] = response_format
            try:
                text = self._send(body)
            except BackendError as exc:
                last_error = exc
                continue
            return Response(content=[TextBlock(text=extract_json(text) if schema else text)])

        if schema is None or attempted_schema_modes == 1:
            raise BackendError(f"request to {self._client.base_url} failed: {last_error}")
        raise BackendError(
            f"every structured-output mode was rejected by {self._client.base_url}: {last_error}"
        )

    @staticmethod
    def _with_schema_instruction(
        messages: list[dict[str, Any]], schema: dict[str, Any]
    ) -> list[dict[str, Any]]:
        instruction = (
            "Respond with a single JSON object and nothing else. It must validate "
            f"against this JSON Schema:\n{json.dumps(schema)}"
        )
        copied = [dict(m) for m in messages]
        if copied and copied[0]["role"] == "system":
            copied[0]["content"] = f"{copied[0]['content']}\n\n{instruction}"
        else:
            copied.insert(0, {"role": "system", "content": instruction})
        return copied

    def _send(self, body: dict[str, Any]) -> str:
        client = self._client
        url = f"{client.base_url.rstrip('/')}/chat/completions"
        headers = {"Authorization": f"Bearer {client.api_key}"}

        for attempt in range(MAX_RETRIES):
            client.throttle.wait()
            try:
                with _hard_deadline(TIMEOUT_S + 15):
                    data = _post_json(url, headers, body)
            except TimeoutError as exc:
                # Surface stalls immediately. A silent retry here is how a run
                # ends up looking alive for hours while doing nothing.
                print(f"  [backend] {exc}, retrying ({attempt + 1}/{MAX_RETRIES})", file=sys.stderr, flush=True)
                if attempt == MAX_RETRIES - 1:
                    raise BackendError(f"request stalled out after {MAX_RETRIES} attempts") from exc
                continue
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode(errors="replace")[:500]
                # 400 means this request shape is wrong - a different schema
                # mode might work, so surface it rather than retrying it.
                if exc.code in (400, 404, 422):
                    raise BackendError(f"HTTP {exc.code}: {detail}") from exc
                if exc.code in (401, 403):
                    raise BackendError(f"HTTP {exc.code} - check NARRATOR_API_KEY: {detail}") from exc
                if attempt == MAX_RETRIES - 1:
                    raise BackendError(f"HTTP {exc.code} after {MAX_RETRIES} attempts: {detail}") from exc
                print(
                    f"  [backend] HTTP {exc.code}, backing off ({attempt + 1}/{MAX_RETRIES})",
                    file=sys.stderr,
                    flush=True,
                )
                time.sleep(min(2**attempt, 60))
                continue
            except urllib.error.URLError as exc:
                if attempt == MAX_RETRIES - 1:
                    raise BackendError(f"network failure after {MAX_RETRIES} attempts: {exc}") from exc
                time.sleep(min(2**attempt, 60))
                continue

            choices = data.get("choices") or []
            if not choices:
                raise BackendError(f"no choices in response: {json.dumps(data)[:500]}")
            content = choices[0].get("message", {}).get("content") or ""

            # An empty completion must never reach the judge. A narration with
            # no text names no entities and states no severity, which scores as
            # a successful entity_omission bypass - so a reasoning model that
            # spends its whole budget on hidden tokens, or any truncated
            # response, would silently inflate the bypass rate instead of
            # failing. Fail loudly.
            if not content.strip():
                finish = choices[0].get("finish_reason", "unknown")
                raise BackendError(
                    f"empty completion (finish_reason={finish}) - refusing to score it "
                    f"as a narration; raise max_tokens or use a non-reasoning model"
                )
            return content

        raise BackendError("exhausted retries")


class OpenAICompatClient:
    """Anthropic-shaped facade over an OpenAI-compatible /chat/completions API."""

    def __init__(self, *, api_key: str, base_url: str, rpm: int = DEFAULT_RPM) -> None:
        self.api_key = api_key
        self.base_url = base_url
        self.throttle = _Throttle(rpm)
        self.messages = _OpenAICompatMessages(self)


def describe_backend() -> str:
    """Human-readable identifier for whichever backend get_client() will pick,
    for recording alongside the numbers."""
    if os.environ.get("NARRATOR_API_KEY"):
        return f"openai-compat:{os.environ.get('NARRATOR_BASE_URL', '<unset>')}"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return "none"


def get_client() -> Any:
    """Return a client for the configured backend.

    NARRATOR_API_KEY wins when both are set, so a run can be pointed at a
    different provider without unsetting an existing Anthropic key.
    """
    api_key = os.environ.get("NARRATOR_API_KEY")
    if api_key:
        base_url = os.environ.get("NARRATOR_BASE_URL")
        if not base_url:
            raise BackendError("NARRATOR_API_KEY is set but NARRATOR_BASE_URL is not")
        return OpenAICompatClient(api_key=api_key, base_url=base_url)

    if os.environ.get("ANTHROPIC_API_KEY"):
        import anthropic

        return anthropic.Anthropic()

    raise BackendError(
        "no model backend configured - set ANTHROPIC_API_KEY, or set "
        "NARRATOR_API_KEY and NARRATOR_BASE_URL for an OpenAI-compatible endpoint"
    )
