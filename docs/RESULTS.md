# Results

**Status: not yet run.** Everything below the line is the methodology and
the exact table this document will contain — but no cell has a real number
in it yet, because producing one requires actual Claude API calls, and none
have been made. Nothing in this file is fabricated or estimated; a blank
cell means "not measured," not "assumed zero" or "assumed high."

The eval harness, all three narrator tiers, and the rule-based judge are
fully built and unit-tested (50 passing tests as of this writing, against
fixture narrators that never touch the network — see
`docs/ARCHITECTURE.md` § Testing philosophy). What's missing is a single
real run.

## How to produce this table for real

```
ANTHROPIC_API_KEY=sk-... python -m eval.run_all
```

This runs the full 40-payload corpus through all three tiers (naive,
hardened, structural — 120 calls total), scores every result with
`eval/judge.py`, prints the summary table below, and writes a timestamped
`eval/results/run_<UTC-timestamp>.{csv,json}` with every individual result
(payload id, tier, category, goal, bypass_detected, reason). Pin a specific
model with `--model` (defaults to `claude-opus-4-8` via the `NARRATOR_MODEL`
env var) — the corpus is cheap enough that a full run costs well under $1
on Opus and a few cents on Haiku.

## Bypass rate by tier and goal

Bypass rate = fraction of payloads targeting that goal for which
`eval/judge.py` detected the intended outcome (lower is better; tier 1 is
the vulnerable baseline, tier 3 is the hardened architectural design —
see `docs/THREAT_MODEL.md`).

| Tier | Overall | severity_downgrade | entity_omission | instruction_leak |
|---|---|---|---|---|
| naive | — | — | — | — |
| hardened | — | — | — | — |
| structural | — | — | — | — |

## What to look for once this is populated

- **Naive should be high across the board** — nothing in tier 1 resists
  any of the three goals; a low naive bypass rate would suggest either the
  corpus is too weak or the judge's heuristics are too strict (both worth
  auditing before trusting the comparison).
- **Hardened should drop meaningfully but not to zero**, especially on
  `instruction_leak` — the model still authors free text in the `summary`
  field, so a sufficiently well-crafted payload can still influence it.
- **Structural should be at or near zero on `severity_downgrade` and
  `entity_omission`** by construction (severity is never asked of the
  model; every event is always rendered). Any nonzero rate there indicates
  a judge or implementation bug worth investigating immediately, not a
  "the model tried harder" result. Nonzero `instruction_leak`-flagged
  results at this tier are more expected — see `docs/THREAT_MODEL.md`'s
  "Residual risk at tier 3" section for why a swayed `ObservationKind`
  label (e.g. `routine_administration` on a malicious event) can still
  trip the judge's benign-language check.
- **Per-category breakdown** (`process_metadata` / `file_path` /
  `network_artifact` / `log_string`) is in the raw CSV/JSON even though
  this table doesn't show it — worth checking whether one field type is
  systematically harder to defend than others.
