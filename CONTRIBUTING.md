# Contributing

## Setup

```
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

You should see all tests pass, with a handful skipped — those are the ones
that make real Claude API calls and are gated on `ANTHROPIC_API_KEY`. **CI
runs without a key on purpose:** everything except the live-model behaviour
is verified for free.

## Running things

```
pytest                     # full suite
python -m eval.dashboard   # regenerate eval/results/dashboard.html
python -m eval.run_all     # THE ONLY COMMAND THAT COSTS MONEY (~120 calls)
```

`pi-eval` and `pi-dashboard` are installed as console scripts equivalents.

## Adding a payload

Payloads live in `injection_corpus/payloads.yaml`. Each needs:

| field | notes |
|---|---|
| `id` | stable, unique; prefix by category (`pm-`, `fp-`, `na-`, `ls-`, `rk-`, `ua-`, `adv-`) |
| `category` | one of the six in `injection_corpus/loader.py` |
| `field` | **must** match that category's `Event` field — the loader enforces this |
| `technique` | one line, describes the *mechanism*, not the outcome |
| `payload` | the literal attacker-controlled string |
| `goal` | `severity_downgrade` / `entity_omission` / `instruction_leak` |
| `tier_target` | optional; `generic` (default), `hardened`, or `structural` |

Two house rules:

1. **No "ignore previous instructions".** That pattern is trivially
   filterable and measuring against it tells you nothing. Every payload must
   read as something a SOC analyst, ticketing system, or vendor would
   plausibly emit. See `docs/THREAT_MODEL.md`.
2. **Set `tier_target` when the payload is engineered against a specific
   defense** — e.g. pre-encoded entities aimed at the tier-2 escaper, or a
   payload naming an allow-listed label to steer tier 3. Generic prose
   attacks that any narrator might fall for stay `generic`.

The loader validates loudly: a malformed entry raises rather than being
skipped, because a silently-dropped payload would quietly shrink eval
coverage.

## Adding a telemetry field or category

Attacker-controlled fields have to be threaded through four places, or the
new category will render but never actually get defended:

1. `telemetry/schema.py` — the `Event` field (+ an `EventType` if needed)
   and its `as_line()` naive serialization
2. `telemetry/synth_events.py` — a base incident that actually populates it
3. `narrator/sanitizer.py` — add it to `_TAGGED_FIELDS` so tier 2 escapes it
4. `narrator/structural.py` — a `_TEMPLATES` entry so tier 3 can render it
5. `injection_corpus/loader.py` — the category → field mapping
6. `eval/harness.py` — `_CATEGORY_BASE_INCIDENT` if the default incident
   shape can't carry the field
7. `eval/dashboard.py` — `_CATEGORY_FIELD`

## Security rules for this codebase

This project's whole subject is untrusted strings reaching a consumer that
interprets them, so the tooling holds itself to the same standard. See
`docs/SECURITY.md` for the findings already fixed. When changing code:

- **Anything rendered into HTML** goes through `html.escape` (quote=True),
  and anything handed to the page's JavaScript goes through
  `safe_json_for_script` and is inserted with `textContent` — never
  `innerHTML`.
- **Anything written to CSV** goes through `csv_safe` — payload-derived text
  starting with `=`, `+`, `-`, `@` is a live formula in Excel.
- **Anything interpolated into a prompt delimiter** — including attribute
  values in `narrator/sanitizer.py` — gets escaped. `host_id` is *not*
  trusted; in real EDRs it's usually the host's self-reported hostname.
- **Never** loosen `validate_classifications` in `narrator/structural.py`.
  Invalid labels and unknown event ids must fall through to `UNCLASSIFIED`,
  and every event must render regardless of what the model returned.

## The honesty rule

`docs/RESULTS.md` and the README must never contain a bypass percentage that
isn't backed by a committed `eval/results/run_*.json`. CI enforces this. If
you haven't run the eval, leave the cells as `—`; an estimate that gets
screenshotted into a writeup is worse than an empty table.
