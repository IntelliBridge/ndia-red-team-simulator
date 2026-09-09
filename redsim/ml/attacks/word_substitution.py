"""TextFooler-style word substitution (spec 12.2 text row; MODALITIES-15, -16, -17).

``word_substitution`` is a black-box, query-counted evasion attack on text
classifiers whose budget ``eps`` is the share of words that may be substituted
(``Norm`` ``"edit"``): per message the attack may replace at most
``ceil(eps * n_words)`` words (at least one, never more than there are). It is
adapter-native, since ART ships no text attack, and follows Jin et al. 2020 in
outline:

1. rank candidate words by leave-one-out importance: delete each eligible word
   and read the drop in the probability of the model's clean prediction (one
   ``predict_proba`` call per message for all deletions);
2. for the most important words in turn, substitute each synonym from the
   lexicon, query the model on every candidate at once, keep the substitution
   that lowers the clean-class probability most, and stop as soon as the
   prediction flips or the budget is spent.

Deviations from the paper, stated on every row and in ``AttackInfo.description``:
no counter-fitted word embeddings (candidates come from a WordNet-derived or
committed synonym table, single alphabetic tokens only), no Universal Sentence
Encoder similarity constraint, no part-of-speech consistency check. Substituted
texts are therefore lexicon-bound and may be ungrammatical or change meaning.
Every substitution is one ``\\w+`` token for one ``\\w+`` token with the
surrounding delimiters kept, so the token count of ``redsim.ml.datasets.sms_spam``
(the model's and the SHAP masker's) is preserved and token attributions align
position by position (MODALITIES-19).

Queries are counted as ``predict_proba`` rows spent by the attack, including the
initial clean prediction the attacker needs; ``queries_mean`` follows the
HopSkipJump convention (rows per sample whose prediction flipped, denominator 0
-> ``None``, totals in the notes). Randomness: a ``numpy`` generator seeded per
run orders synonym candidates when a lexicon returns more than
``max_candidates``; nothing else is random.

``text_noise_control`` is the matching benign control (spec 12.4): the same number
of words per message replaced by random words drawn from the evaluation slice's
own vocabulary at random positions, seeded, with no model query. It never
creates a Finding. The campaign records its rows under the shared control row id
``m.control.noise.eps<eps>`` so the control predicate and interpretation rules
apply unchanged.

The lexicon (``SynonymLexicon``) is resolved from the target first
(``target.synonym_lexicon()``: the bundled target reads ``<assets>/lexicons``, the
test double returns the committed ``tests/ml/fixtures/synonyms_synthetic_tiny.json``), then
from ``NLTK_DATA`` (the sandbox child pins it to the asset tree's WordNet copy).
Without any lexicon the attack raises ``LexiconUnavailable`` (an
``AttackNotApplicable``) and the campaign records it ``not_run``; nothing is
invented. WordNet is read through ``nltk`` from a local directory only.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar

import numpy as np

from redsim.ml.attacks import NONDETERMINISM_PREFIX, library_versions, resolve_from_schema
from redsim.ml.attacks.base import AttackOutput
from redsim.ml.datasets.sms_spam import tokenize, word_spans
from redsim.ml.errors import AttackNotApplicable
from redsim.ml.schema import AttackInfo, ParamSpec
from redsim.ml.targets.base import Target

ATTACK_ID = "word_substitution"
CONTROL_ID = "text_noise_control"
# The spec 12.3 edit-budget grid for text (MODALITIES-02 / -15): share of words substituted; fits the (0, 1] validator.
DEFAULT_EDIT_GRID: tuple[float, ...] = (0.1, 0.2, 0.3)
DEFAULT_EDIT_REFERENCE = 0.2
NLTK_DATA_ENV = "NLTK_DATA"
_ALPHA_TOKEN = re.compile(r"^[^\W\d_]+$", re.UNICODE)   # single alphabetic token (no digits, no underscore)

DEVIATIONS_NOTE = ("TextFooler-style deviations: no counter-fitted embeddings (lexicon synonyms only), no Universal "
                   "Sentence Encoder similarity constraint, no part-of-speech consistency check; substitutions are "
                   "lexicon-bound and may be ungrammatical or change meaning")
QUERIES_DENOMINATOR_NOTE = ("queries_mean denominator = samples flipped from the model's clean prediction (the "
                            "query cost of one successful decision-boundary crossing); the rate over all attacked "
                            "samples is recorded beside it")
TOKEN_COUNT_NOTE = ("token count preserved: every substitution replaces one \\w+ token with one \\w+ token and keeps "
                    "the surrounding delimiters, so SHAP token attributions align position by position")
NOT_APPLICABLE_NORMS_NOTE = "linf_norm_mean / l2_norm_mean are not defined for text (recorded as nan by the adapter)"
SEEDED_ORDER_NOTE = "seeded candidate order (numpy default_rng(seed)); no other randomness in the attack"
CONTROL_NOTE = "random word swaps at the same edit budget as the attack; gradient-free, no model query"


class LexiconUnavailable(AttackNotApplicable):
    """No synonym lexicon could be resolved for this target; the attack is recorded not_run."""

    code = "lexicon_unavailable"


# --------------------------------------------------------------------------------------- lexicon

def _clean_synonyms(word: str, candidates: Sequence[str]) -> tuple[str, ...]:
    """Lowercase, single alphabetic tokens, without the word itself, deduplicated in a stable sorted order."""
    out: set[str] = set()
    for c in candidates:
        s = str(c).strip().lower().replace("_", " ")
        if " " in s or not s or s == word or not _ALPHA_TOKEN.match(s):
            continue
        out.add(s)
    return tuple(sorted(out))


class SynonymLexicon:
    """``synonyms(word) -> list[str]`` with a recorded source and digest (spec 11.5 provenance).

    Build one with ``from_mapping`` (an in-memory table), ``from_json`` (a committed JSON file: either a
    ``{word: [synonyms]}`` table, optionally under a ``synonyms`` key, such as
    ``tests/ml/fixtures/synonyms_synthetic_tiny.json``, or the WordNet excerpt written by
    ``redsim.ml.assets.fixture_sample.write_synonyms_tiny`` with ``entries[lemma] = {pos, synonyms}``, such as
    ``tests/ml/fixtures/synonyms_tiny.json``) or ``from_nltk_data`` (a local ``nltk_data`` directory holding
    ``corpora/wordnet``; nothing is downloaded). Lookups are lowercase; results are single alphabetic tokens.
    """

    def __init__(self, lookup: Callable[[str], Sequence[str]], *, sha256: str, source: str,
                 license: str | None = None, size: int | None = None) -> None:
        self._lookup = lookup
        self._cache: dict[str, tuple[str, ...]] = {}
        self.sha256 = sha256
        self.source = source
        self.license = license
        self.size = size

    def synonyms(self, word: str) -> list[str]:
        key = word.lower()
        if key not in self._cache:
            try:
                raw = self._lookup(key)
            except Exception:  # noqa: BLE001 - a lexicon lookup failure means "no synonyms", never a crash
                raw = ()
            self._cache[key] = _clean_synonyms(key, raw)
        return list(self._cache[key])

    def describe(self) -> dict[str, Any]:
        return {"source": self.source, "sha256": self.sha256, "license": self.license, "size": self.size}

    @classmethod
    def from_mapping(cls, table: Mapping[str, Sequence[str]], *, source: str = "inline",
                     license: str | None = None) -> SynonymLexicon:
        clean = {str(k).lower(): [str(v) for v in vs] for k, vs in table.items()}
        blob = json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return cls(lambda w: clean.get(w, ()), sha256=hashlib.sha256(blob).hexdigest(), source=source,
                   license=license, size=len(clean))

    @classmethod
    def from_json(cls, path: Path) -> SynonymLexicon:
        path = Path(path)
        if not path.is_file():
            raise LexiconUnavailable(f"synonym lexicon not found: {path}")
        raw = path.read_bytes()
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise LexiconUnavailable(f"synonym lexicon {path} is not valid JSON: {exc}") from exc
        table: object = data.get("synonyms", data) if isinstance(data, dict) else None
        if isinstance(data, dict) and "synonyms" not in data and isinstance(data.get("entries"), dict):
            # WordNet excerpt from redsim.ml.assets.fixture_sample.write_synonyms_tiny: entries[lemma] = {pos, synonyms}
            table = {k: v.get("synonyms", []) for k, v in data["entries"].items() if isinstance(v, dict)}
        if not isinstance(table, dict) or not all(isinstance(v, list) for v in table.values()):
            raise LexiconUnavailable(f"synonym lexicon {path} must map words to lists of synonyms")
        license_ = data.get("license") if isinstance(data, dict) else None
        clean = {str(k).lower(): [str(v) for v in vs] for k, vs in table.items()}
        return cls(lambda w: clean.get(w, ()), sha256=hashlib.sha256(raw).hexdigest(), source=f"json:{path.name}",
                   license=str(license_) if isinstance(license_, str) else None, size=len(clean))

    @classmethod
    def from_nltk_data(cls, path: Path) -> SynonymLexicon:
        """WordNet from a local ``nltk_data`` directory (``<path>/corpora/wordnet``); offline, digest recorded."""
        root = Path(path) / "corpora" / "wordnet"
        if not root.is_dir():
            raise LexiconUnavailable(f"no WordNet corpus under {Path(path) / 'corpora' / 'wordnet'}; run "
                                     "`redsim ml build-assets --dataset text` to fetch it")
        try:
            from nltk.corpus.reader.wordnet import WordNetCorpusReader
            from nltk.data import FileSystemPathPointer
        except ImportError as exc:
            raise LexiconUnavailable(f"nltk is not installed in this build ({exc}); the WordNet lexicon cannot be "
                                     "read") from exc
        files = sorted(p for p in root.iterdir() if p.is_file() and (p.name.startswith(("data.", "index."))))
        if not files:
            raise LexiconUnavailable(f"{root} holds no WordNet data/index files")
        h = hashlib.sha256()
        for p in files:
            h.update(p.name.encode("utf-8"))
            h.update(p.read_bytes())
        try:
            reader = WordNetCorpusReader(FileSystemPathPointer(str(root)), None)
        except Exception as exc:  # noqa: BLE001 - nltk raises several classes for a broken corpus directory
            raise LexiconUnavailable(f"WordNet under {root} could not be opened: {exc}") from exc

        def lookup(word: str) -> list[str]:
            return [lemma.name() for synset in reader.synsets(word) for lemma in synset.lemmas()]

        return cls(lookup, sha256=h.hexdigest(), source=f"wordnet:{root}",
                   license="WordNet 3.0 License (Princeton University)", size=None)


def resolve_lexicon(target: Any) -> SynonymLexicon:
    """The lexicon for ``target``: ``target.synonym_lexicon()`` first, then WordNet under ``NLTK_DATA``.

    Raises ``LexiconUnavailable`` (an ``AttackNotApplicable``) when neither yields one.
    """
    getter = getattr(target, "synonym_lexicon", None)
    if callable(getter):
        found = getter()
        if isinstance(found, SynonymLexicon):
            return found
        if found is not None:
            raise LexiconUnavailable(f"target.synonym_lexicon() returned {type(found).__name__}, not a SynonymLexicon")
    nltk_dir = os.environ.get(NLTK_DATA_ENV, "").strip()
    if nltk_dir and (Path(nltk_dir) / "corpora" / "wordnet").is_dir():
        return SynonymLexicon.from_nltk_data(Path(nltk_dir))
    raise LexiconUnavailable("no synonym lexicon available: the target bundles none under <assets>/lexicons and "
                             f"{NLTK_DATA_ENV} points at no WordNet corpus; the attack cannot propose substitutions")


# --------------------------------------------------------------------------------------- text edits

def edit_budget(eps: float, n_words: int) -> int:
    """``min(n_words, max(1, ceil(eps * n_words)))``: at least one word when the text has any (spec 12.3 text row)."""
    if n_words <= 0:
        return 0
    return min(n_words, max(1, math.ceil(float(eps) * n_words - 1e-9)))


def match_case(original: str, replacement: str) -> str:
    """Carry the original token's casing pattern (UPPER, Title, else lower) onto the replacement."""
    if original.isupper() and len(original) > 1:
        return replacement.upper()
    if original[:1].isupper():
        return replacement[:1].upper() + replacement[1:]
    return replacement


def substitute(text: str, span: tuple[int, int], replacement: str) -> str:
    start, end = span
    return text[:start] + replacement + text[end:]


def delete_word(text: str, spans: Sequence[tuple[int, int]], position: int) -> str:
    """Remove one word and one adjacent delimiter run (so no doubled separators remain)."""
    start, end = spans[position]
    if position + 1 < len(spans):
        end = spans[position + 1][0]        # eat the delimiter that follows
    elif position > 0:
        start = spans[position - 1][1]      # last word: eat the delimiter before it
    return text[:start] + text[end:]


def _as_texts(x: Any) -> list[str]:
    items = x.tolist() if isinstance(x, np.ndarray) else list(x)
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise AttackNotApplicable(f"text attacks expect message strings, got {type(item).__name__}")
        out.append(item)
    return out


def slice_vocabulary(texts: Sequence[str]) -> list[str]:
    """Sorted lowercase words of the evaluation slice (the control's draw pool)."""
    return sorted({w.lower() for t in texts for w in tokenize(t)})


# --------------------------------------------------------------------------------------- the attack

class WordSubstitutionAdapter:
    id = ATTACK_ID
    domains = frozenset({"text"})
    takes_eps = True
    norms: ClassVar[frozenset[str]] = frozenset({"edit"})
    capabilities: ClassVar[frozenset[str]] = frozenset({"adversarial_ml", "black_box", "query_counted", "takes_eps",
                                                        "family:evasion", "modality:text", "norm:edit"})

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="eps", type="float", default=DEFAULT_EDIT_REFERENCE, min=1e-6, max=1.0,
                  description=("Edit budget: share of a message's words that may be substituted "
                               "(ceil(eps * n_words), at least 1); the campaign grid supplies it.")),
        ParamSpec(name="max_candidates", type="int", default=8, min=1, max=32,
                  description="Synonyms tried per substituted word (seeded order when the lexicon offers more)."),
        ParamSpec(name="min_word_len", type="int", default=3, min=1, max=20,
                  description="Words shorter than this are never substituted."),
        ParamSpec(name="preserve_case", type="bool", default=True,
                  description="Carry the original word's casing onto the synonym."),
    ]

    def __init__(self, lexicon: SynonymLexicon | None = None) -> None:
        self._lexicon = lexicon

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="Word substitution (TextFooler-style, lexicon-bound, black-box)", domain="text",
            family="evasion",
            description=("Greedy leave-one-out word importance ranking followed by synonym substitution from a "
                         "WordNet-derived lexicon, stopping at the first prediction flip or when the edit budget "
                         "(share of words) is spent. Black-box: predict_proba queries only, counted. "
                         + DEVIATIONS_NOTE + "."),
            params_schema=list(self._schema),
            references=["Jin, Jin, Zhou, Szolovits 2020 (TextFooler), arXiv:1907.11932",
                        "Morris et al. 2020 (TextAttack), arXiv:2005.05909",
                        "Princeton WordNet 3.0 (synonym lexicon, fetched at build time as nltk_data)"],
            phase="B", access="black-box", requires_gradients=False, status="available", reason=None,
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        return resolve_from_schema(self._schema, params)

    def lexicon_for(self, target: Any) -> SynonymLexicon:
        return self._lexicon if self._lexicon is not None else resolve_lexicon(target)

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        p = self.resolve_params(params)
        eps = float(p["eps"])
        max_candidates = int(p["max_candidates"])
        min_len = int(p["min_word_len"])
        preserve_case = bool(p["preserve_case"])
        texts = _as_texts(x)
        n = len(texts)
        lexicon = self.lexicon_for(target)
        rng = np.random.default_rng(int(seed))
        counter = {"rows": 0, "calls": 0}

        def predict(batch: Sequence[str]) -> np.ndarray:
            counter["rows"] += len(batch)
            counter["calls"] += 1
            return np.asarray(target.predict_proba(np.asarray(list(batch), dtype=object)), dtype=np.float64)

        t0 = time.perf_counter()
        proba_clean = predict(texts) if n else np.empty((0, 0))
        y_clean = proba_clean.argmax(axis=1) if n else np.empty(0, dtype=np.int64)
        adv: list[str] = []
        substituted = 0
        words_total = 0
        n_flipped = 0
        n_no_candidates = 0
        for i, text in enumerate(texts):
            spans = word_spans(text)
            n_words = len(spans)
            words_total += n_words
            c = int(y_clean[i])
            budget = edit_budget(eps, n_words)
            eligible: list[tuple[int, list[str]]] = []
            for pos, (s, e) in enumerate(spans):
                word = text[s:e]
                if len(word) < min_len:
                    continue
                syns = lexicon.synonyms(word)
                if syns:
                    eligible.append((pos, syns))
            if budget == 0 or not eligible:
                n_no_candidates += 1
                adv.append(text)
                continue
            # 1. leave-one-out importance: one predict call for every eligible deletion of this message.
            deleted = [delete_word(text, spans, pos) for pos, _ in eligible]
            p_del = predict(deleted)[:, c]
            p_ref = float(proba_clean[i, c])
            importance = p_ref - p_del
            order = sorted(range(len(eligible)), key=lambda j: (-float(importance[j]), eligible[j][0]))
            # 2. greedy substitution in importance order until a flip or the budget is spent.
            current = text
            current_spans = list(spans)
            p_current = p_ref
            used = 0
            flipped = False
            for j in order:
                if used >= budget:
                    break
                pos, syns = eligible[j]
                candidates = list(syns)
                if len(candidates) > max_candidates:
                    candidates = [candidates[k] for k in rng.permutation(len(candidates))[:max_candidates].tolist()]
                s, e = current_spans[pos]
                original = current[s:e]
                variants = [substitute(current, (s, e), match_case(original, syn) if preserve_case else syn)
                            for syn in candidates]
                proba = predict(variants)
                p_c = proba[:, c]
                best = int(np.argmin(p_c))
                flips = np.flatnonzero(proba.argmax(axis=1) != c)
                if flips.size:
                    best = int(flips[np.argmin(p_c[flips])])
                if float(p_c[best]) >= p_current and not flips.size:
                    continue                    # no candidate lowers the clean-class probability: skip the word
                current = variants[best]
                current_spans = word_spans(current)
                if len(current_spans) != n_words:  # pragma: no cover - guarded by the alphabetic-token filter
                    raise AttackNotApplicable("a substitution changed the token count; the lexicon returned a "
                                              "multi-token synonym")
                p_current = float(p_c[best])
                used += 1
                substituted += 1
                if flips.size:
                    flipped = True
                    break
            if flipped:
                n_flipped += 1
            adv.append(current)
        wall = time.perf_counter() - t0

        rows, calls = counter["rows"], counter["calls"]
        per_attacked = rows / n if n else 0.0
        queries_mean: float | None
        if n_flipped > 0:
            queries_mean = rows / n_flipped
            queries_note = (f"queries_mean = {queries_mean:.1f} predict rows per flipped sample ({rows} rows in "
                            f"{calls} predict calls; {n_flipped}/{n} samples flipped from the model's clean "
                            f"prediction; {per_attacked:.1f} rows per attacked sample)")
        else:
            queries_mean = None
            queries_note = (f"queries_mean not computed (denominator 0: 0/{n} samples flipped from the model's clean "
                            f"prediction); {rows} predict rows in {calls} predict calls were spent "
                            f"({per_attacked:.1f} rows per attacked sample)")
        realised = (substituted / words_total) if words_total else 0.0
        notes = [
            (f"edit budget: eps={eps:g} -> at most ceil(eps * n_words) words per message (at least 1, so on short "
             f"messages the realised share can exceed eps by up to 1/n_words); substituted {substituted} of "
             f"{words_total} words over {n} messages (realised edit fraction {realised:.4f} overall)"),
            f"{n_no_candidates}/{n} messages had no eligible word (shorter than min_word_len={min_len} or no synonym "
            "in the lexicon) and were returned unchanged",
            "black-box: predict_proba queries only, no gradients, no surrogate", queries_note, QUERIES_DENOMINATOR_NOTE,
            DEVIATIONS_NOTE, TOKEN_COUNT_NOTE, NOT_APPLICABLE_NORMS_NOTE,
            f"lexicon: source={lexicon.source}, sha256={lexicon.sha256}"
            + (f", license={lexicon.license}" if lexicon.license else ""),
            f"{NONDETERMINISM_PREFIX}{SEEDED_ORDER_NOTE}",
        ]
        return AttackOutput(
            x_adv=np.asarray(adv, dtype=object), linf_norm_mean=float("nan"), l2_norm_mean=float("nan"),
            wall_time_s=wall, params=dict(p), library_versions=library_versions(), queries_mean=queries_mean,
            notes=notes,
        )


# --------------------------------------------------------------------------------------- the control

class TextRandomSwapControl:
    """Benign control for text (spec 12.4): random word swaps at the attack's edit budget, no model access."""

    id = CONTROL_ID
    domains = frozenset({"text"})
    takes_eps = True
    norms: ClassVar[frozenset[str]] = frozenset({"edit"})
    capabilities: ClassVar[frozenset[str]] = frozenset({"adversarial_ml", "black_box", "takes_eps", "family:control",
                                                        "modality:text", "norm:edit"})

    _schema: ClassVar[list[ParamSpec]] = [
        ParamSpec(name="eps", type="float", default=DEFAULT_EDIT_REFERENCE, min=1e-6, max=1.0,
                  description="Edit budget mirrored from the attack grid: share of words swapped per message."),
        ParamSpec(name="preserve_case", type="bool", default=True,
                  description="Carry the original word's casing onto the random replacement."),
    ]

    def info(self) -> AttackInfo:
        return AttackInfo(
            id=self.id, name="Benign random word-swap control (text)", domain="text", family="control",
            description=("Same messages with the same number of words replaced by random words from the "
                         "evaluation slice's vocabulary at random positions; separates synonym-directed failure "
                         "from ordinary sensitivity to word changes. Never creates a Finding."),
            params_schema=list(self._schema),
            references=["spec section 12.4 (benign random-noise control), text analogue"],
            phase="B", access="black-box", requires_gradients=False, status="available", reason=None,
        )

    def resolve_params(self, params: dict[str, Any]) -> dict[str, float | int | bool]:
        return resolve_from_schema(self._schema, params)

    def run(self, target: Target, x: np.ndarray, y: np.ndarray,
            params: dict[str, float | int | bool], seed: int) -> AttackOutput:
        p = self.resolve_params(params)
        eps = float(p["eps"])
        preserve_case = bool(p["preserve_case"])
        texts = _as_texts(x)
        vocabulary = slice_vocabulary(texts)
        rng = np.random.default_rng(int(seed))
        t0 = time.perf_counter()
        out: list[str] = []
        swapped = 0
        words_total = 0
        for text in texts:
            spans = word_spans(text)
            n_words = len(spans)
            words_total += n_words
            k = edit_budget(eps, n_words)
            if k == 0 or len(vocabulary) < 2:
                out.append(text)
                continue
            positions = sorted(int(v) for v in rng.choice(n_words, size=k, replace=False))
            current = text
            for pos in positions:
                s, e = word_spans(current)[pos]
                original = current[s:e]
                pool = [w for w in vocabulary if w != original.lower()]
                replacement = str(pool[int(rng.integers(0, len(pool)))])
                current = substitute(current, (s, e), match_case(original, replacement) if preserve_case else replacement)
                swapped += 1
            out.append(current)
        wall = time.perf_counter() - t0
        realised = (swapped / words_total) if words_total else 0.0
        notes = [
            (f"random word swaps: eps={eps:g} -> ceil(eps * n_words) words per message (at least 1); swapped "
             f"{swapped} of {words_total} words over {len(texts)} messages (realised edit fraction {realised:.4f})"),
            f"vocabulary = the {len(vocabulary)} distinct lowercase words of the evaluation slice",
            CONTROL_NOTE, TOKEN_COUNT_NOTE, NOT_APPLICABLE_NORMS_NOTE,
            f"{NONDETERMINISM_PREFIX}random word swaps drawn with numpy default_rng(seed)",
        ]
        return AttackOutput(
            x_adv=np.asarray(out, dtype=object), linf_norm_mean=float("nan"), l2_norm_mean=float("nan"),
            wall_time_s=wall, params=dict(p), library_versions=library_versions(), notes=notes,
        )


ADAPTER: WordSubstitutionAdapter = WordSubstitutionAdapter()
CONTROL: TextRandomSwapControl = TextRandomSwapControl()

__all__ = [
    "ADAPTER", "ATTACK_ID", "CONTROL", "CONTROL_ID", "CONTROL_NOTE", "DEFAULT_EDIT_GRID", "DEFAULT_EDIT_REFERENCE",
    "DEVIATIONS_NOTE", "NLTK_DATA_ENV", "NOT_APPLICABLE_NORMS_NOTE", "QUERIES_DENOMINATOR_NOTE", "TOKEN_COUNT_NOTE",
    "LexiconUnavailable", "SynonymLexicon", "TextRandomSwapControl", "WordSubstitutionAdapter", "delete_word",
    "edit_budget", "match_case", "resolve_lexicon", "slice_vocabulary", "substitute",
]
