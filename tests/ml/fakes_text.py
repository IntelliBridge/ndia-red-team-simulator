"""Text test double (spec 11.1, 22; MODALITIES-14/-25) and the pre-B0 schema shim for the text tests.

``TinyTextTarget`` satisfies the ``Target`` protocol with a seeded scikit-learn
``TfidfVectorizer + LogisticRegression`` pipeline fitted at construction on a
synthetic three-topic vocabulary (cooking, gardening, astronomy), so attack,
explain and runner tests need no corpus, no asset tree and no network. Its
``synonym_lexicon()`` returns the committed ``tests/ml/fixtures/synonyms_synthetic_tiny.json``.
It lives only under ``tests/``: no API path serves it and nothing it produces is
evidence.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

from redsim.ml.datasets.sampling import stratified_indices
from redsim.ml.datasets.sms_spam import MASKER_SPLIT_PATTERN, NGRAM_RANGE, TOKEN_PATTERN, tokenize
from redsim.ml.errors import AttackNotApplicable
from redsim.ml.schema import TargetInfo
from redsim.ml.targets.base import Sample

FIXTURES = Path(__file__).parent / "fixtures"
SYNONYMS_TINY = FIXTURES / "synonyms_synthetic_tiny.json"

TEXT_CLASS_NAMES: list[str] = ["cooking", "gardening", "astronomy"]
TEXT_DATASET = "synthetic_text"
TOPIC_WORDS: dict[int, list[str]] = {
    0: ["recipe", "oven", "bake", "flour", "simmer", "skillet", "garlic", "spatula"],
    1: ["compost", "seedling", "trowel", "mulch", "pruning", "greenhouse", "perennial", "soil"],
    2: ["telescope", "nebula", "orbit", "eclipse", "comet", "galaxy", "meteor", "lunar"],
}
FILLER: list[str] = ["the", "and", "with", "from", "into", "over", "near", "after", "before", "during", "please",
                     "today", "again", "very", "morning", "evening"]
_N_TRAIN_PER_CLASS = 40
_N_EVAL_PER_CLASS = 12


def _message(rng: np.random.Generator, topic: int, index: int) -> str:
    """Seven words: four topic words and three fillers, shuffled, with a little punctuation and casing variety."""
    words = [str(rng.choice(TOPIC_WORDS[topic])) for _ in range(4)] + [str(rng.choice(FILLER)) for _ in range(3)]
    rng.shuffle(words)
    words[0] = words[0].capitalize()
    text = " ".join(words)
    if index % 3 == 0:
        text = text.replace(" ", ", ", 1)
    if index % 2 == 0:
        text += "."
    if index % 5 == 0:
        text = "(" + text + ")"
    return text


def synthetic_corpus(seed: int, per_class: int, offset: int = 0) -> tuple[list[str], np.ndarray]:
    rng = np.random.default_rng(seed)
    texts: list[str] = []
    labels: list[int] = []
    for i in range(per_class * len(TEXT_CLASS_NAMES)):
        topic = i % len(TEXT_CLASS_NAMES)
        texts.append(_message(rng, topic, i + offset))
        labels.append(topic)
    return texts, np.asarray(labels, dtype=np.int64)


class TinyTextTarget:
    """Seeded TF-IDF + logistic regression on a synthetic 3-topic corpus; strings in, probabilities out."""

    id = "tiny_text"

    def __init__(self, seed: int = 0, *, lexicon: bool = True) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline

        self._seed = int(seed)
        train_texts, train_y = synthetic_corpus(seed, _N_TRAIN_PER_CLASS)
        self._eval_texts, self._eval_y = synthetic_corpus(seed + 1000, _N_EVAL_PER_CLASS, offset=7)
        self._pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(token_pattern=TOKEN_PATTERN, lowercase=True, ngram_range=NGRAM_RANGE)),
            ("logreg", LogisticRegression(C=10.0, max_iter=1000, random_state=self._seed)),
        ]).fit(train_texts, train_y)
        self._with_lexicon = bool(lexicon)
        self._lexicon: Any = None

    # -- protocol ---------------------------------------------------------------------------------

    def info(self) -> TargetInfo:
        return TargetInfo(id=self.id, name="Tiny synthetic text classifier (test double)", domain="text",
                          status="available",
                          metadata={"dataset": TEXT_DATASET, "n_classes": len(TEXT_CLASS_NAMES), "gradients": False,
                                    "text": self.text_spec()})

    def load(self) -> None:
        return None

    def sample(self, n: int, seed: int) -> Sample:
        idx = stratified_indices(self._eval_y, n, seed)
        return Sample(x=np.asarray([self._eval_texts[int(i)] for i in idx], dtype=object),
                      y=self._eval_y[idx].astype(np.int64), indices=np.asarray(idx, dtype=np.int64),
                      class_names=list(TEXT_CLASS_NAMES))

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        texts = [str(t) for t in (x.tolist() if isinstance(x, np.ndarray) else list(x))]
        if not texts:
            return np.empty((0, len(TEXT_CLASS_NAMES)), dtype=np.float32)
        return np.asarray(self._pipeline.predict_proba(texts), dtype=np.float32)

    def art_classifier(self) -> Any:
        raise AttackNotApplicable("no ART estimator for text; text attacks are adapter-native (test double)")

    def torch_model(self) -> Any:
        return None

    def sklearn_model(self) -> Any:
        return self._pipeline

    def text_spec(self) -> dict[str, Any]:
        vec = self._pipeline.named_steps["tfidf"]
        return {"tokenizer_regex": TOKEN_PATTERN, "masker_split_regex": MASKER_SPLIT_PATTERN, "lowercase": True,
                "ngram_range": list(NGRAM_RANGE), "vocabulary_size": int(len(vec.vocabulary_)),
                "max_words": int(max(len(tokenize(t)) for t in self._eval_texts))}

    def synonym_lexicon(self) -> Any:
        if not self._with_lexicon:
            return None
        if self._lexicon is None:
            from redsim.ml.attacks.word_substitution import SynonymLexicon

            self._lexicon = SynonymLexicon.from_json(SYNONYMS_TINY)
        return self._lexicon

    def manifest(self) -> dict[str, Any]:
        lr = self._pipeline.named_steps["logreg"]
        digest = hashlib.sha256(np.ascontiguousarray(lr.coef_).tobytes() + np.ascontiguousarray(lr.intercept_).tobytes()
                                ).hexdigest()
        lexicon = self.synonym_lexicon()
        return {
            "dataset": TEXT_DATASET, "dataset_id": TEXT_DATASET, "split": "eval", "model": "TfidfVectorizer+LogisticRegression",
            "format": "sklearn_joblib", "weights_sha256": digest, "sha256": digest, "seed": self._seed,
            "class_names": list(TEXT_CLASS_NAMES), "torch_model": None, "gradients": False,
            "text": self.text_spec(), "explainer": "PartitionExplainer over shap.maskers.Text",
            "lexicon": None if lexicon is None else lexicon.describe(),
            "caveats": ["synthetic three-topic corpus generated by a seeded rule; a test double, never evidence about "
                        "any dataset"],
            "eval_n": int(self._eval_y.shape[0]),
        }


def tiny_tsv(path: Path, *, n_per_class: int = 20, seed: int = 0) -> Path:
    """A small inline ``<label>\\t<message>`` corpus in the UCI layout (ham / spam), for training tests.

    Stands in for the committed ``tests/ml/fixtures/sms_spam_sample.tsv`` that wave B0 adds; the messages are
    synthetic and never described as SMS Spam Collection data.
    """
    rng = np.random.default_rng(seed)
    ham_words = ["meeting", "lunch", "tomorrow", "thanks", "call", "home", "later", "movie", "dinner", "okay"]
    spam_words = ["win", "prize", "free", "claim", "urgent", "cash", "text", "reply", "offer", "award"]
    lines: list[str] = []
    for i in range(n_per_class):
        ham = " ".join(str(rng.choice(ham_words)) for _ in range(6)) + f" {i}"
        spam = " ".join(str(rng.choice(spam_words)) for _ in range(6)) + f" {i}!"
        lines.append(f"ham\t{ham}")
        lines.append(f"spam\t{spam}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def fixture_lexicon_words() -> set[str]:
    data = json.loads(SYNONYMS_TINY.read_text(encoding="utf-8"))
    return {str(k) for k in data["synonyms"]}


__all__ = [
    "FILLER", "SYNONYMS_TINY", "TEXT_CLASS_NAMES", "TEXT_DATASET", "TOPIC_WORDS", "TinyTextTarget",
    "fixture_lexicon_words", "synthetic_corpus", "tiny_tsv",
]
