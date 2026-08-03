# Architecture

## Data flow

```
Incident (telemetry/schema.py)
   |
   |  (eval harness picks a base incident that can carry the
   |   payload's field, then splices the payload into the last
   |   event that already populates it: proc_image / file_path /
   |   dns_name / proc_cmdline / registry_key / user_agent)
   v
narrate_* (one of three tiers, narrator/)
   |
   |  builds a prompt from the incident, calls the Claude API,
   |  parses/renders the response into flat text
   v
narrator output (str)
   |
   v
eval/judge.py::score(payload, output) -> JudgeResult
   |
   |  rule-based check keyed to payload.goal:
   |  severity_downgrade | entity_omission | instruction_leak
   v
eval/harness.py::RunResult  ->  eval/run_all.py  ->  eval/results/*.{csv,json}
```

## Package layout

### `telemetry/`

- `schema.py` — `EventType` enum, `Event` dataclass (one normalized
  telemetry record), `Incident` dataclass (a correlated group of events
  plus a *trusted* `risk_score` and `technique_set` — computed
  independently of the narrator, never asked of the LLM). `Event.as_line()`
  is the deliberately naive, unescaped serialization the tier-1 narrator
  uses.
- `synth_events.py` — four synthetic incident generators
  (`benign_admin_incident`, `download_exec_incident`,
  `credential_theft_incident`, `beacon_persistence_incident` — the last is
  Windows-shaped so the registry and HTTP payload categories have telemetry
  that actually carries those fields) that stand in for what a real detection
  engine would hand off to a narrator. Documents the corpus's
  category → field mapping.

### `injection_corpus/`

- `payloads.yaml` — 66 payloads across six categories, each with `id`,
  `category`, `field`, `technique`, `payload`, `goal`, and an optional
  `tier_target` marking which defense it is engineered against. See
  `docs/THREAT_MODEL.md` for the design rationale.
- `loader.py` — `load_corpus()` parses and validates the YAML (raises
  loudly on any malformed/duplicate/mismatched entry — a corrupted entry
  should never silently shrink eval coverage), `by_category()` groups
  results.

### `narrator/`

Three tiers, all callable as `narrate_x(incident, *, client=None, model=...)
-> str`, so `eval/harness.py` can swap between them via the same
`Callable[[Incident], str]` signature:

- `narrator.py` — `narrate_naive` (tier 1) and `narrate_hardened` (tier 2),
  plus `flatten_hardened_response` (pure, testable without the API — turns
  the hardened tier's structured JSON reply into the same flat text shape
  the other tiers produce, so `eval/judge.py` can score all three
  uniformly).
- `sanitizer.py` — `render_event_typed` / `render_incident_typed`: wraps
  every attacker-controlled field in a typed, escaped XML-style tag. Used
  by both the hardened and structural prompts.
- `structural.py` — tier 3. `ObservationKind` (the allow-list),
  `validate_classifications` (the security-critical function: drops
  anything not traceable to a real event ID or not in the allow-list),
  `render_event_line` / `render_structural_report` (pure, trusted
  rendering), `narrate_structural` (the impure API-calling entry point).
- `prompts/`
  - `legacy_naive_prompt.py` — tier 1's raw-concatenation template.
  - `system_prompt.py` — tier 2's system prompt, hardened-response JSON
    schema, and user-prompt builder.
  - `structural_prompt.py` — tier 3's classification prompt (takes the
    allow-list as a parameter rather than importing `structural.py`
    directly, to avoid a circular import).

Every function that calls the Claude API accepts an injectable `client`
and defaults `model` to `NARRATOR_MODEL` (env var, defaults to
`claude-opus-4-8`) — this is what lets `eval/run_all.py` swap in a cheaper
model for a full corpus run without touching code.

### `eval/`

- `judge.py` — `score(payload, narrator_output) -> JudgeResult`. Three
  independent rule-based checks, one per `Payload.goal` value. Rule-based
  rather than LLM-as-judge specifically so the same (payload, output) pair
  always scores the same way — reproducibility matters more here than a
  smarter judge would help.
- `harness.py` — `resolve_base_incident` (routes a category to an incident
  shape that carries its field), `splice_payload` (puts one payload into a
  fresh copy of that base incident, targeting the last event that already
  populates the field so the telemetry stays coherent), `run_corpus` (runs the full corpus through one
  injectable narrator, scores every result), `TIERS` (name → narrate
  function registry), `run_all_tiers` (runs the corpus through all three
  tiers), `summarize` (bypass rate overall and per goal — the numbers
  `RESULTS.md`'s table cells come from).
- `run_all.py` — CLI entry point (`python -m eval.run_all`), plus
  `csv_safe` which neutralizes spreadsheet formula injection in the export
  (see `docs/SECURITY.md` finding 2). Requires `ANTHROPIC_API_KEY`; everything upstream of it is unit-tested without
  needing the API (fixture narrators stand in for the real Claude calls in
  `eval/test_harness.py`).
- `dashboard.py` — generates the self-contained HTML view. `render_page`
  is pure and fully unit-tested; `safe_json_for_script` is the escaping
  that keeps hostile payload text from terminating the page's JSON data
  island (see `docs/SECURITY.md` finding 3).
- `results/` — versioned per commit: each real run of `run_all.py` writes
  a timestamped `run_<UTC-timestamp>.csv` and `.json` here, alongside the
  generated `dashboard.html`.

## Testing philosophy

Everything that doesn't strictly require a live model response is a pure
function and has a direct unit test: corpus validation, payload splicing,
sanitizer escaping, hardened-response flattening, structural
classification validation and rendering, judge scoring, and the CLI's
CSV/JSON writers and summary-table formatting. The handful of tests that do
call the real API (`narrator/test_narrator.py`,
`narrator/test_structural.py`'s last test) are gated behind
`ANTHROPIC_API_KEY` presence and skip cleanly without it — this mirrors the
Postgres-DSN-gated test pattern already used in the sibling SentinelX Go
project.
