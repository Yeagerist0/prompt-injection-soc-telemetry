"""An automated attacker that writes its own payloads.

`docs/RESULTS.md` ends on an admission: nine payloads hand-engineered against
the prompt-hardened tier and four against the structural tier landed nothing
on the tiers they targeted, and `instruction_leak` came in at 0% for every
tier including naive. The honest reading is not that the defenses hold. It is
that a corpus written by one person stops at that person's imagination, and
n=9 cannot distinguish "the mechanics hold" from "the attacks were not good
enough."

This replaces the imagination with a search. A model proposes payloads for a
(field, goal, tier), the existing harness splices and runs them, the existing
judge scores them, and what survived is fed back as the next round's examples.

Either outcome is worth having. If it finds bypasses the hand-written corpus
missed, the defense numbers were optimistic and now we know by how much. If a
few hundred directed attempts still cannot beat the structural tier, that is a
far stronger claim than "my four payloads didn't work."
"""
