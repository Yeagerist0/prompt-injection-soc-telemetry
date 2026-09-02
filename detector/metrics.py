"""Scoring, with the threshold chosen the way a deployment would choose it.

ROC-AUC is threshold-free and flatters everything on a balanced-ish set. What
a SOC actually asks is: at a false-positive rate we can live with, how much do
we catch? Every telemetry field on every event passes through this thing, so a
1% false-positive rate is already thousands of alerts a day - and that is the
*generous* budget used here.

The threshold is fitted once on the validation split and then applied
unchanged to every test split. Picking a per-split threshold that maximises
that split's own numbers is how a detector gets reported as working when it
does not.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


@dataclass(frozen=True)
class Report:
    split: str
    n: int
    n_pos: int
    n_neg: int
    roc_auc: float
    pr_auc: float
    threshold: float
    recall: float
    fpr: float
    precision: float
    recall_on_hard_negatives_fpr: float
    # Recall when the threshold is refitted on this split's own negatives to
    # hit the budget exactly. It is an oracle number - a deployment cannot see
    # the test set - and it exists only so two models can be compared at the
    # same false-positive rate. Comparing recall across models whose achieved
    # FPRs differ by 3x is comparing nothing.
    matched_fpr_recall: float
    matched_fpr_threshold: float

    def as_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        return (
            f"{self.split:<12} n={self.n:<5} ROC {self.roc_auc:.3f}  PR {self.pr_auc:.3f}  "
            f"recall {self.recall:.3f}  FPR {self.fpr:.3f}  "
            f"FPR(hard neg) {self.recall_on_hard_negatives_fpr:.3f}  "
            f"recall@matched-1%FPR {self.matched_fpr_recall:.3f}"
        )


def threshold_at_fpr(scores: np.ndarray, labels: np.ndarray, target_fpr: float) -> float:
    """Lowest threshold whose false-positive rate on `labels==0` is <= target.

    Lowest, not highest: among thresholds that meet the budget we want the one
    that catches the most.
    """
    negatives = np.sort(scores[labels == 0])[::-1]
    if len(negatives) == 0:
        return 0.5
    allowed = int(np.floor(target_fpr * len(negatives)))
    if allowed >= len(negatives):
        return float(negatives[-1])
    # Just above the (allowed+1)-th highest negative score, so exactly
    # `allowed` negatives clear it.
    return float(np.nextafter(negatives[allowed], np.inf))


def evaluate(
    split_name: str,
    scores: np.ndarray,
    labels: np.ndarray,
    threshold: float,
    hard_negative_mask: np.ndarray | None = None,
    matched_fpr: float = 0.01,
) -> Report:
    labels = np.asarray(labels)
    scores = np.asarray(scores, dtype=float)
    pos, neg = labels == 1, labels == 0
    predicted = scores >= threshold

    tp = int((predicted & pos).sum())
    fp = int((predicted & neg).sum())

    hard_fpr = float("nan")
    if hard_negative_mask is not None and hard_negative_mask.any():
        hard_fpr = float(predicted[hard_negative_mask].mean())

    matched_t = threshold_at_fpr(scores, labels, matched_fpr)
    matched_recall = float((scores[pos] >= matched_t).mean()) if pos.any() else float("nan")

    return Report(
        split=split_name,
        n=len(labels),
        n_pos=int(pos.sum()),
        n_neg=int(neg.sum()),
        roc_auc=float(roc_auc_score(labels, scores)) if pos.any() and neg.any() else float("nan"),
        pr_auc=float(average_precision_score(labels, scores)) if pos.any() and neg.any() else float("nan"),
        threshold=float(threshold),
        recall=tp / max(1, int(pos.sum())),
        fpr=fp / max(1, int(neg.sum())),
        precision=tp / max(1, tp + fp),
        recall_on_hard_negatives_fpr=hard_fpr,
        matched_fpr_recall=matched_recall,
        matched_fpr_threshold=float(matched_t),
    )
