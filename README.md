# prompt-injection-soc-telemetry

Indirect prompt injection in AI-augmented SOC/EDR tooling: an LLM asked to
narrate raw security telemetry is reading attacker-controlled strings
(process names, command lines, file paths, DNS names, registry keys, user
agents) as if they were neutral facts. This repo builds a synthetic EDR pipeline, a 66-payload
injection corpus across six attacker-controlled fields, disguised as
legitimate SOC/vendor content (not "ignore previous instructions"), and
three narrator defense tiers - naive, prompt-hardened, and
structurally-grounded - to measure how much each tier actually helps.
Some payloads are engineered against a specific tier rather than being
generic prose, so the eval can tell a real defense from one that only
stops easy attacks.

**Core finding this project is built to test:** prompt-level defenses
reduce bypass rate but don't eliminate it; closing the gap requires
constraining what the model can structurally produce, not just what it's
told to do. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Results

**Not yet measured against the live API** - see
[`docs/RESULTS.md`](docs/RESULTS.md) for the full methodology and the
table this section will be replaced with once a real run has happened.
Nothing here is estimated or fabricated in the meantime.

```
ANTHROPIC_API_KEY=sk-... python -m eval.run_all
```

## Dashboard

```
python -m eval.dashboard        # -> eval/results/dashboard.html
```

Self-contained HTML (no build step, no external requests): a payload-by-tier
matrix of all 66 payloads grouped by attack category, with search and
filters, a click-through detail panel showing each payload's raw text and
what every tier did with it, tier bypass rates, and a per-attacker-goal
breakdown. It reads the newest `eval/results/run_*.json`
if one exists; until then the three result columns render as explicitly
not-measured rather than as zeros or estimates, while the rest of the page
(payload ids, techniques, goals, category to field mapping) is real data read
straight from the corpus.

## Layout

```
telemetry/          typed EDR-style event/incident schema + synthetic incident generators
injection_corpus/   66 payloads across 6 categories + a validating loader
narrator/           three narrator tiers (naive / hardened / structurally-grounded)
eval/               splices payloads into incidents, runs a narrator tier, scores bypasses
                    + dashboard.py, a self-contained HTML view of the results
docs/               ARCHITECTURE.md, THREAT_MODEL.md, RESULTS.md, SECURITY.md
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full data flow
and per-module breakdown.

## Setup

```
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to add payloads or new
telemetry fields, and [`docs/SECURITY.md`](docs/SECURITY.md) for the
self-audit findings (the tooling renders hostile strings, so it holds itself
to the same standard it studies).

## Running the tests

```
pytest
```

Every test that doesn't require a live model response (corpus validation,
payload splicing, sanitizer escaping, structural-tier classification
validation and rendering, judge scoring, CLI output formatting) runs with
no API access needed. Tests that do call the Claude API
(`narrator/test_narrator.py`, one test in `narrator/test_structural.py`)
skip cleanly if `ANTHROPIC_API_KEY` is unset.

## Running the eval

```
ANTHROPIC_API_KEY=sk-... python -m eval.run_all
# or, cheaper:
ANTHROPIC_API_KEY=sk-... python -m eval.run_all --model claude-haiku-4-5
```

Writes a timestamped `eval/results/run_<UTC-timestamp>.{csv,json}` with
every individual (tier, payload, bypass_detected, reason) result, and
prints the summary table. The full 66-payload x 3-tier run is ~198 short
API calls - well under $1 even on Opus.

`ant auth login` lets the SDK pick up an OAuth session instead of an
exported `ANTHROPIC_API_KEY`, but note that it only changes *how you
authenticate* - `/v1/messages` still bills against Console API credits
either way. A Claude.ai Pro/Max chat subscription does not include API
credit; the two are separate products.
