"""Two models that are not the point, and exist to make the point checkable.

`LengthOnly` is the control. It sees two numbers per example - character count
and whitespace-token count - and nothing else. Whatever it scores is the floor:
any model that does not clearly beat it has learned that injections are long.
This is the same control that killed the first version of a probe I built on
GPT-2, where 100% accuracy at layer 0 turned out to be prompt length.

`CharNgram` is the cheap-but-real baseline: TF-IDF over character 3-5 grams
into logistic regression. It trains in seconds on CPU and it is genuinely hard
to beat on short strings with distinctive punctuation. If a fine-tuned
transformer cannot beat it, the honest conclusion is to ship this instead.
"""
from __future__ import annotations

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


class LengthOnly:
    name = "length_only_control"

    def __init__(self) -> None:
        self._pipe = Pipeline(
            [("scale", StandardScaler()), ("lr", LogisticRegression(max_iter=1000))]
        )

    @staticmethod
    def _features(texts: list[str]) -> np.ndarray:
        return np.array([[len(t), len(t.split())] for t in texts], dtype=float)

    def fit(self, texts: list[str], labels: list[int]) -> "LengthOnly":
        self._pipe.fit(self._features(texts), labels)
        return self

    def score(self, texts: list[str]) -> np.ndarray:
        return self._pipe.predict_proba(self._features(texts))[:, 1]


class CharNgram:
    name = "char_ngram_lr"

    def __init__(self) -> None:
        self._pipe = Pipeline([
            ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
            ("lr", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")),
        ])

    def fit(self, texts: list[str], labels: list[int]) -> "CharNgram":
        self._pipe.fit(texts, labels)
        return self

    def score(self, texts: list[str]) -> np.ndarray:
        return self._pipe.predict_proba(texts)[:, 1]
