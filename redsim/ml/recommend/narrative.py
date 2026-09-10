"""LLM writer layer via Pythia (spec section 16.3).

A presentation layer over the rule output: the model may rephrase the ranked
candidates for a technical reader but may add no claim, number or
recommendation. The payload is text only (the deterministic summary plus the
rule rows). The response is scrubbed with ``guard_output``, then rejected
outright when it contains a number absent from the payload or a banned word;
a rejected or failed narrative leaves the rule output standing
(``narrative=None``, ``narrative_source="rules"``). Nothing here can fail a
campaign.

Where it runs (spec 10.8, 16.1): in the **worker parent** on the default pool,
after the sandbox child has returned its record. The child never holds a Pythia
key (its environment is stripped, ``redsim.ml.sandbox_worker`` scrubs ``PYTHIA_*``
again) and never calls this module on its own; ``redsim.ml.campaign.run_campaign``
only applies a narrative when an offline caller injects ``narrative_settings``
explicitly. :func:`narrate` is the parent's entry point: it returns a
:class:`NarrativeOutcome` carrying the prompt and completion texts (for the
``ml.harden.prompt`` / ``ml.harden.completion`` artifacts), their digests and the
token usage (for the ``harden.execute`` audit row and the ``LLMUsage`` row) next
to the rewritten candidates; :func:`build_narrative` / :func:`add_narrative` are
the thin text-only views over it.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from redsim.llm.guardrails import GuardrailViolation, guard_input, guard_output
from redsim.llm.pythia import ChatBackend, PythiaSettings, chat_text, make_backend
from redsim.ml.schema import BANNED_SCORE_WORDS, CandidateRecommendation

logger = logging.getLogger(__name__)

#: Heading the UI and the ``ml.harden.narrative`` artifact print above LLM prose (spec 16.3).
NARRATIVE_LABEL_TEMPLATE = "LLM-generated narrative of rule outputs (via Pythia, {model})"

# The frozen score-word ban (schema.BANNED_SCORE_WORDS) plus the writer's own certainty words.
BANNED_WORDS: tuple[str, ...] = tuple(dict.fromkeys(
    ("validated", "proven", "guaranteed", *BANNED_SCORE_WORDS, "deployment ready")))

SYSTEM_PROMPT = """You rewrite the rule outputs of an adversarial-ML robustness evaluation into concise plain-language prose for a technical reader.

Contract, in order of priority:
1. Keep every number identical to the input and cite no number that is not present in the input. Do not convert fractions to percentages, do not round, do not estimate.
2. Add no recommendation, cause, claim, or comparison that is not present in the input. Do not speculate about training data, architecture, or deployment.
3. Describe every recommendation as a candidate and state that none has been evaluated on this model.
4. Never state or estimate a gain, improvement range, or magnitude; direction only, as the input states it.
5. Do not use the words "validated", "proven", "guaranteed", "hardened", "deployment-ready", "certified", or "safe".
6. SHAP attributions describe the model's sensitivity, not the cause of a failure; keep that framing.

Format: one short paragraph per candidate recommendation, in the given order, each starting with the candidate id in square brackets, for example "[r.R6] ...". No headings, no bullet lists, no preamble."""

# standalone number tokens only: not glued to an identifier (m.evasion.fgsm.eps0.03, r.R6) or a preceding dot
_NUMBER = re.compile(r"(?<![A-Za-z0-9_.])\d+(?:\.\d+)?(?![A-Za-z0-9_])")
_REC_MARK = re.compile(r"\[(r\.[A-Za-z0-9_]+)\]")


def build_payload(recs: list[CandidateRecommendation], summary_text: str) -> str:
    """The user message: the deterministic text summary plus the ranked rule rows. Text only."""
    lines = ["EVALUATION SUMMARY (measurements, scorecard, explanation aggregates, limitations):", summary_text.strip(),
             "", "RANKED CANDIDATE RECOMMENDATIONS (rule outputs; status candidate, none evaluated on this model):"]
    for i, r in enumerate(recs, 1):
        lines.append(f"{i}. [{r.id}] {r.title}")
        lines.append(f"   rationale: {r.rationale}")
        lines.append(f"   triggered_by: {', '.join(r.triggered_by)}")
        if r.references:
            lines.append(f"   references: {'; '.join(r.references)}")
    return "\n".join(lines)


def _numbers(text: str) -> set[str]:
    out: set[str] = set()
    for tok in _NUMBER.findall(text):
        out.add(tok)
        try:
            out.add(repr(float(tok)))
        except ValueError:
            pass
    return out


def check_numeric_consistency(narrative: str, payload: str) -> str | None:
    """Reason string when the narrative carries a number token absent from the payload, else ``None``."""
    allowed = _numbers(payload)
    missing = sorted({tok for tok in _NUMBER.findall(narrative)
                      if tok not in allowed and repr(float(tok)) not in allowed})
    if missing:
        return f"numbers not present in the payload: {', '.join(missing[:8])}"
    return None


def check_banned_words(narrative: str) -> str | None:
    low = narrative.lower()
    hits = [w for w in BANNED_WORDS if re.search(r"(?<![a-z-])" + re.escape(w) + r"(?![a-z-])", low)]
    return f"banned words: {', '.join(hits)}" if hits else None


def split_by_recommendation(narrative: str, rec_ids: list[str]) -> dict[str, str] | None:
    """Map rec id -> its paragraph when the narrative follows the ``[r.X]`` format for every rec, else ``None``."""
    marks = list(_REC_MARK.finditer(narrative))
    if not marks:
        return None
    sections: dict[str, str] = {}
    for idx, m in enumerate(marks):
        end = marks[idx + 1].start() if idx + 1 < len(marks) else len(narrative)
        text = narrative[m.end():end].strip()
        if text:
            sections.setdefault(m.group(1), text)
    if all(r in sections for r in rec_ids):
        return sections
    return None


def _sha256(text: str | None) -> str | None:
    return None if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest()


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def usage_from_response(response: dict[str, Any] | None) -> tuple[int | None, int | None]:
    """``(prompt_tokens, completion_tokens)`` from an OpenAI-style ``usage`` block; ``None`` when absent."""
    if not isinstance(response, dict):
        return None, None
    usage = response.get("usage")
    if not isinstance(usage, dict):
        return None, None
    return _int_or_none(usage.get("prompt_tokens")), _int_or_none(usage.get("completion_tokens"))


class _RecordingBackend:
    """Wrap a ``ChatBackend`` so the raw response (with its ``usage`` block) survives ``chat_text``."""

    def __init__(self, inner: ChatBackend) -> None:
        self.inner = inner
        self.last_response: dict[str, Any] | None = None

    def chat(self, model: str, messages: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        response = self.inner.chat(model, messages, **kwargs)
        self.last_response = response if isinstance(response, dict) else None
        return response


@dataclass
class NarrativeOutcome:
    """Everything the worker parent records about one narrative attempt (spec 5.11 ``harden.execute``).

    ``status`` is ``"ok"`` or the skip / rejection reason. ``prompt`` is the exact user message sent
    (``None`` when no call was attempted); ``completion`` is the scrubbed response text (``None`` when
    the call failed before a response). Texts become the ``ml.harden.prompt`` / ``ml.harden.completion``
    artifacts; only the digests and token counts travel on the audit row. ``narrative_source`` is
    ``"llm"`` only when ``status == "ok"``.
    """

    recommendations: list[CandidateRecommendation]
    status: str
    narrative_source: str = "rules"
    model: str | None = None
    prompt: str | None = None
    completion: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    called: bool = False
    text: str | None = None
    settings_redacted: dict[str, Any] | None = field(default=None)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def prompt_sha256(self) -> str | None:
        return _sha256(self.prompt)

    @property
    def completion_sha256(self) -> str | None:
        return _sha256(self.completion)

    def label(self) -> str:
        return NARRATIVE_LABEL_TEMPLATE.format(model=self.model or "unknown")

    def narrative_markdown(self) -> str | None:
        """The ``ml.harden.narrative`` artifact body: the label line, then the text as displayed."""
        if not self.ok or not self.text:
            return None
        return f"{self.label()}\n\n{self.text}\n"

    @property
    def responded(self) -> bool:
        """A response came back (text or a usage block): the call consumed tokens and is metered."""
        return self.called and (
            self.completion is not None or self.prompt_tokens is not None or self.completion_tokens is not None
        )

    def audit_detail(self) -> dict[str, Any]:
        """The narrative fields of the ``harden.execute`` row: digests, counts, redacted settings; never text.

        Token counts travel as ``usage: {"prompt", "completion"}``: the audit redactor
        (``redsim.audit.redact``) blanks any key containing ``token``, so the spec 5.11
        names ``prompt_tokens`` / ``completion_tokens`` would be written as ``<REDACTED>``.
        """
        return {
            "llm_used": self.ok,
            "narrative_source": self.narrative_source,
            "narrative_status": self.status,
            "skipped_reason": None if self.ok else self.status,
            "llm": dict(self.settings_redacted) if self.settings_redacted else None,
            "model": self.model,
            "prompt_sha256": self.prompt_sha256,
            "completion_sha256": self.completion_sha256,
            "usage": {"prompt": self.prompt_tokens, "completion": self.completion_tokens},
        }

    def provenance_llm(self) -> dict[str, Any] | None:
        """``Provenance.llm`` (spec 14.4): redacted settings plus hashes and usage; ``None`` unless generated."""
        if not self.ok:
            return None
        return {
            **dict(self.settings_redacted or {}),
            "model": self.model,
            "prompt_sha256": self.prompt_sha256,
            "response_sha256": self.completion_sha256,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
        }


def _attach(recs: list[CandidateRecommendation], text: str) -> list[CandidateRecommendation]:
    sections = split_by_recommendation(text, [r.id for r in recs])
    out: list[CandidateRecommendation] = []
    for r in recs:
        para = sections[r.id] if sections is not None else text
        out.append(r.model_copy(update={"narrative": para, "narrative_source": "llm"}))
    return out


def narrate(recs: list[CandidateRecommendation], summary_text: str, settings: PythiaSettings | None, *,
            backend: ChatBackend | None = None, config: Any = None) -> NarrativeOutcome:
    """One narrative attempt with full provenance; never raises.

    Order: input guard on the assembled payload -> ``chat_text`` (one non-streaming turn through the
    Pythia backend, wrapped so the raw ``usage`` block is kept) -> output guard (secret scrub) -> the
    banned-word and numeric-consistency post-checks. Any failure returns the untouched candidates with
    ``narrative_source="rules"`` and the reason in ``status``.
    """
    recs = list(recs)
    redacted = None
    if settings is not None:
        redacted_fn = getattr(settings, "redacted", None)
        redacted = dict(redacted_fn()) if callable(redacted_fn) else None
    model = getattr(settings, "model", None) if settings is not None else None
    outcome = NarrativeOutcome(recommendations=recs, status="not configured", model=model,
                               settings_redacted=redacted)
    if settings is None:
        return outcome
    if not recs:
        outcome.status = "no recommendations to narrate"
        return outcome
    payload = build_payload(recs, summary_text)
    try:
        guard_input(payload, config=config)
    except GuardrailViolation as exc:
        outcome.status = f"rejected by input guard ({exc})"
        return outcome
    except Exception as exc:  # noqa: BLE001 -- guardrails must never fail the job
        outcome.status = f"input guard unavailable ({type(exc).__name__})"
        return outcome
    try:
        recording = _RecordingBackend(backend or make_backend(settings))
    except Exception as exc:  # noqa: BLE001 -- backend construction (TLS context, SDK) is not evidence
        outcome.status = f"unavailable ({type(exc).__name__})"
        return outcome
    outcome.prompt = payload
    outcome.called = True
    try:
        text = chat_text(settings, SYSTEM_PROMPT, payload, backend=recording)
    except Exception as exc:  # noqa: BLE001 -- HTTP errors, timeouts, response shape: degrade to rules
        outcome.prompt_tokens, outcome.completion_tokens = usage_from_response(recording.last_response)
        outcome.status = f"unavailable ({type(exc).__name__})"
        return outcome
    outcome.prompt_tokens, outcome.completion_tokens = usage_from_response(recording.last_response)
    try:
        text = guard_output(text, config=config)
    except Exception as exc:  # noqa: BLE001
        outcome.status = f"output guard unavailable ({type(exc).__name__})"
        return outcome
    text = (text or "").strip()
    outcome.completion = text
    if not text:
        outcome.status = "rejected by post-check (empty response)"
        return outcome
    reason = check_banned_words(text) or check_numeric_consistency(text, payload)
    if reason:
        outcome.status = f"rejected by post-check ({reason})"
        return outcome
    outcome.status = "ok"
    outcome.narrative_source = "llm"
    outcome.text = text
    outcome.recommendations = _attach(recs, text)
    return outcome


def build_narrative(recs: list[CandidateRecommendation], summary_text: str, settings: PythiaSettings | None, *,
                    backend: ChatBackend | None = None, config: Any = None) -> tuple[str | None, str]:
    """``(narrative_text, status)``; text is ``None`` unless status is ``"ok"``. Never raises."""
    outcome = narrate(recs, summary_text, settings, backend=backend, config=config)
    return (outcome.text if outcome.ok else None), outcome.status


def add_narrative(recs: list[CandidateRecommendation], summary_text: str, settings: PythiaSettings | None, *,
                  backend: ChatBackend | None = None, config: Any = None) -> list[CandidateRecommendation]:
    """Attach LLM prose to the candidates; a no-op copy when ``settings`` is ``None`` or the narrative is rejected.

    Ids, titles, rationales, triggering ids and references are never changed.
    When the response carries one ``[r.X]`` paragraph per candidate each gets
    its own; otherwise every candidate carries the full narrative so the UI
    shows the same text below the rule cards.
    """
    recs = list(recs)
    if settings is None or not recs:
        return recs
    outcome = narrate(recs, summary_text, settings, backend=backend, config=config)
    if not outcome.ok:
        logger.info("LLM narrative: %s; rule output stands", outcome.status)
        return recs
    return outcome.recommendations
