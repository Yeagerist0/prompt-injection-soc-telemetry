"""Fine-tunes a small encoder to score a single telemetry field value.

Written as an explicit loop rather than `Trainer` because the interesting
parts here are the ones a high-level API hides: which checkpoint gets kept,
what the validation metric is, and the fact that selection happens on PR-AUC
rather than accuracy. On a mostly-benign stream, accuracy is maximised by
predicting "benign" forever.

Runs on CPU. Sequences are short (a field value, not a document), so 96
tokens covers the corpus with room to spare and the whole run is minutes.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass

import numpy as np
import torch
from sklearn.metrics import average_precision_score
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer

DEFAULT_MODEL = "distilroberta-base"
MAX_LEN = 96


@dataclass
class TrainConfig:
    model_name: str = DEFAULT_MODEL
    epochs: int = 3
    batch_size: int = 32
    lr: float = 2e-5
    warmup_frac: float = 0.1
    weight_decay: float = 0.01
    seed: int = 20260902


class _Texts(Dataset):
    def __init__(self, texts: list[str], labels: list[int], tok) -> None:
        self.enc = tok(texts, truncation=True, max_length=MAX_LEN, padding="max_length", return_tensors="pt")
        self.labels = torch.tensor(labels, dtype=torch.long)

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, i: int) -> dict:
        return {k: v[i] for k, v in self.enc.items()} | {"labels": self.labels[i]}


def _seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


class TransformerDetector:
    name = "distilroberta_ft"

    def __init__(self, cfg: TrainConfig | None = None) -> None:
        self.cfg = cfg or TrainConfig()
        self.name = self.cfg.model_name.split("/")[-1].replace("-", "_") + "_ft"
        self._tok = None
        self._model = None

    def fit(
        self,
        texts: list[str],
        labels: list[int],
        val_texts: list[str],
        val_labels: list[int],
        *,
        log=print,
    ) -> "TransformerDetector":
        cfg = self.cfg
        _seed_everything(cfg.seed)

        self._tok = AutoTokenizer.from_pretrained(cfg.model_name)
        self._model = AutoModelForSequenceClassification.from_pretrained(cfg.model_name, num_labels=2)

        loader = DataLoader(_Texts(texts, labels, self._tok), batch_size=cfg.batch_size, shuffle=True)
        opt = torch.optim.AdamW(self._model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)
        total = len(loader) * cfg.epochs
        warmup = max(1, int(total * cfg.warmup_frac))

        def lr_at(step: int) -> float:
            if step < warmup:
                return step / warmup
            return max(0.0, (total - step) / max(1, total - warmup))

        sched = torch.optim.lr_scheduler.LambdaLR(opt, lr_at)

        best_ap, best_state = -1.0, None
        step = 0
        for epoch in range(cfg.epochs):
            self._model.train()
            running = 0.0
            for batch in loader:
                opt.zero_grad()
                out = self._model(**batch)
                out.loss.backward()
                torch.nn.utils.clip_grad_norm_(self._model.parameters(), 1.0)
                opt.step()
                sched.step()
                running += out.loss.item()
                step += 1
            ap = average_precision_score(val_labels, self.score(val_texts))
            log(f"  epoch {epoch + 1}/{cfg.epochs}  train loss {running / len(loader):.4f}  val PR-AUC {ap:.4f}")
            if ap > best_ap:
                best_ap = ap
                best_state = {k: v.detach().clone() for k, v in self._model.state_dict().items()}

        if best_state is not None:
            self._model.load_state_dict(best_state)
            log(f"  kept the epoch with val PR-AUC {best_ap:.4f}")
        return self

    @torch.no_grad()
    def score(self, texts: list[str], batch_size: int = 64) -> np.ndarray:
        assert self._model is not None and self._tok is not None, "fit() first"
        self._model.eval()
        out = []
        for i in range(0, len(texts), batch_size):
            enc = self._tok(
                texts[i : i + batch_size], truncation=True, max_length=MAX_LEN,
                padding=True, return_tensors="pt",
            )
            logits = self._model(**enc).logits
            out.append(torch.softmax(logits, dim=-1)[:, 1].numpy())
        return np.concatenate(out) if out else np.zeros(0)
