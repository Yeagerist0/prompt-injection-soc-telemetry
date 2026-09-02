# Automating the attacker

`docs/RESULTS.md` ends on an admission. Nine payloads hand-engineered against
the prompt-hardened tier and four against the structural tier landed **nothing**
on the tiers they targeted, and `instruction_leak` came in at 0% for every tier
including naive. The reading I wrote down at the time still stands: that is a
decent sign for the defenses and a bad sign for the corpus. n=9 cannot
distinguish "the mechanics hold" from "the attacks were not good enough."

The fix is to stop relying on one person's imagination and search instead.

## What I tried first, and why it does not work

`redteam/attacker.py` asks a model to propose payloads for a given (field,
goal, tier), feeds back what worked, and iterates. It is written, tested, and
it does not run, because of what the available models do with the request:

| model | result |
|---|---|
| `gemini-3.5-flash` | **refuses.** "Sorry, I cannot fulfill your request to generate prompt injection payloads designed to evade detection or deceive security analysis tools." |
| `gemini-3.1-pro-preview` | HTTP 429, `limit: 0` — not available on this key at any volume |
| `gemini-2.5-flash` | retired for new users |
| `gemini-2.5-flash-lite` | HTTP 429, quota-zero |

The refusal is the interesting one, and I am recording it rather than working
around it. The prompt already states the true context — authorised red-teaming
of a published defensive benchmark, synthetic telemetry, no real system — and
the model declined anyway. Engineering a prompt to get past that is
jailbreaking, and it is not something I am willing to do to make a benchmark
number look better.

So the practical finding for anyone building this kind of evaluation:
**LLM-driven attack generation against your own defenses is gated by your
provider's safety policy**, and a benchmark that depends on it inherits that
gate. You need either a provider with an explicit red-teaming allowance, a
local model, or an attacker that is not a model at all.

## What replaced it

`redteam/operators.py` and `redteam/evolve.py`: a seeded evolutionary search
over typed mutation operators. It cannot refuse, costs no calls to generate,
and is reproducible from a seed, which sampled model output is not.

**Seeds** are the hand-written corpus payloads for the goal being attacked, so
the search starts where the human effort stopped rather than from nothing.

**Operators** are small and composable — append a directive, add a fabricated
sign-off or ticket, close a tag, forge a JSON fragment, forge a conversation
turn, name an allow-listed label, obfuscate with zero-width or RTL characters,
add a self-reference, and **shorten**. That last one matters more than it
looks: without an operator that can make a payload shorter, the search only
ever climbs toward longer strings, and "the attack works" becomes
indistinguishable from "the attack is long."

**Crossover** takes the head of one parent and the tail of another, keeping the
carrier that makes a string a plausible field value while importing another
payload's mechanism.

## The three things that would make its output meaningless

**It optimises the judge, not an analyst.** Stated plainly because it cannot be
designed away: selection uses `eval/judge.py`'s verdict, so what the search
finds are *judge-visible* bypasses, and each one needs a human to read the
narration before it counts. Two things stop that from being circular. The
continuous fitness that breaks ties between non-bypassing candidates is built
from a **different vocabulary** than the judge's — the judge asks "did the
narrator call this safe", the fitness asks "how much of the incident's
seriousness survived" — and a test asserts the two word lists are disjoint. And
every reported winner's full narration is saved in the results file, so the
reading is possible rather than promised.

**A "new" bypass could be a rediscovery.** Every candidate is compared against
the hand-written corpus by Jaccard similarity over character 6-shingles and
labelled if it is a near-duplicate, so "found something the corpus missed"
means what it says. The threshold is deliberately low: mislabelling a genuine
novelty costs one candidate, mislabelling a rediscovery corrupts the claim.

**A bypass could be a one-off.** Hosted endpoints are not deterministic even at
temperature 0 — `docs/RESULTS.md` records a truncation that happened on one
attempt and not the next. Every winner is re-run and re-judged with a fresh
call before it is reported.

## Running it

```
export NARRATOR_API_KEY=... NARRATOR_BASE_URL=... NARRATOR_MODEL=...
python -m redteam.evolve --tier hardened --generations 5 --population 12
python -m redteam.evolve --tier structural --goal severity_downgrade
```

Every call is counted against `--max-calls` and the search stops at the
ceiling rather than draining a quota. Identical genomes are cached, so elites
carried between generations cost nothing.

Results land in `redteam/results/evolve_<tier>_<stamp>.json` with every
individual, its fitness, its verdict, and the narration each winner produced.
