"""LLM writer layer via Pythia (spec section 16.3).

A presentation layer over the rule output: the model may rephrase the ranked
candidates for a technical reader but may add no claim, number or
recommendation. The payload is text only (the deterministic summary plus the
rule rows). The response is scrubbed with ``guard_output``, then rejected
outright when it contains a number absent from the payload or a banned word;
a rejected or failed narrative leaves the rule output standing
(``narrative=None``, ``narrative_source="rules"``). Nothing here can fail a
campaign.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from redsim.llm.guardrails import GuardrailViolation, guard_input, guard_output
from redsim.llm.pythia import ChatBackend, PythiaSettings, chat_text
from redsim.ml.schema import BANNED_SCORE_WORDS, CandidateRecommendation

logger = logging.getLogger(__name__)

# The frozen score-word ban (schema.BANNED_SCORE_WORDS) plus the writer's own validation words.
BANNED_WORDS: tuple[str, ...] = tuple(dict.fromkeys(
    ("validated", "proven", "guaranteed", *BANNED_SCORE_WORDS, "deployment ready")))

SYSTEM_PROMPT = """You rewrite the rule outputs of an adversarial-ML robustness evaluation into concise plain-language prose for a technical reader.

Contract, in order of priority:
1. Keep every number identical to the input and cite no number that is not present in the input. Do not convert fractions to percentages, do not round, do not estimate.
2. Add no recommendation, cause, claim, or comparison that is not present in the input. Do not speculate about training data, architecture, or deployment.
3. Describe every recommendation as a candidate and state that none has been evaluated on this model unless the input includes a measured delta MRI.
4. Never state or estimate an expected gain, improvement range, or magnitude; direction only, as the input states it.
5. Do not use the words "validated", "proven", "guaranteed", "hardened", "deployment-ready", "certified", or "safe".
6. SHAP attributions describe the model's sensitivity, not the cause of a failure; keep that framing.

Format: one short paragraph per candidate recommendation, in the given order, each starting with the candidate id in square brackets, for example "[r.R6] ...". No headings, no bullet lists, no preamble."""

# standalone number tokens only: not glued to an identifier (m.evasion.fgsm.eps0.03, r.R6) or a preceding dot
_NUMBER = re.compile(r"(?<![A-Za-z0-9_.])\d+(?:\.\d+)?(?![A-Za-z0-9_])")
_REC_MARK = re.compile(r"\[(r\.[A-Za-z0-9_]+)\]")


def build_payload(recs: list[CandidateRecommendation], summary_text: str) -> str:
    """The user message: the deterministic text summary plus the ranked rule rows. Text only."""
    lines = ["EVALUATION SUMMARY (measurements, scorecard, explanation aggregates, limitations):", summary_text.strip(),
             "", "RANKED CANDIDATE RECOMMENDATIONS (rule outputs; status candidate, validation not evaluated):"]
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


def build_narrative(recs: list[CandidateRecommendation], summary_text: str, settings: PythiaSettings | None, *,
                    backend: ChatBackend | None = None, config: Any = None) -> tuple[str | None, str]:
    """``(narrative_text, status)``; text is ``None`` unless status is ``"ok"``. Never raises."""
    if settings is None:
        return None, "not configured"
    if not recs:
        return None, "no recommendations to narrate"
    payload = build_payload(recs, summary_text)
    try:
        guard_input(payload, config=config)
    except GuardrailViolation as exc:
        return None, f"rejected by input guard ({exc})"
    except Exception as exc:  # noqa: BLE001 -- guardrails must never fail the job
        return None, f"input guard unavailable ({type(exc).__name__})"
    try:
        text = chat_text(settings, SYSTEM_PROMPT, payload, backend=backend)
    except Exception as exc:  # noqa: BLE001 -- HTTP errors, timeouts, response shape: degrade to rules
        return None, f"unavailable ({type(exc).__name__})"
    try:
        text = guard_output(text, config=config)
    except Exception as exc:  # noqa: BLE001
        return None, f"output guard unavailable ({type(exc).__name__})"
    text = (text or "").strip()
    if not text:
        return None, "rejected by post-check (empty response)"
    reason = check_banned_words(text) or check_numeric_consistency(text, payload)
    if reason:
        return None, f"rejected by post-check ({reason})"
    return text, "ok"


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
    text, status = build_narrative(recs, summary_text, settings, backend=backend, config=config)
    if text is None:
        logger.info("LLM narrative: %s; rule output stands", status)
        return recs
    sections = split_by_recommendation(text, [r.id for r in recs])
    out: list[CandidateRecommendation] = []
    for r in recs:
        para = sections[r.id] if sections is not None else text
        out.append(r.model_copy(update={"narrative": para, "narrative_source": "llm"}))
    return out
