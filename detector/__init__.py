"""A learned detector for instruction-carrying telemetry fields.

Tiers 1-3 defend the narrator. This asks a different question: can a small
model look at a single attacker-controlled field value - a process path, a
command line, a DNS name - and tell whether it is carrying an instruction,
before the narrator ever sees it?

The whole design is built around one failure mode. Injected field values are
longer and more English-like than real ones, so a classifier can score well
by learning "long, wordy string" and nothing else. Every part of this package
exists to make that impossible to mistake for a result: hard negatives that
are benign but wordy, a length-only control model that runs on every
evaluation, and a test split whose attack techniques never appear in training.
"""
