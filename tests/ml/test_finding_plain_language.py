"""The layman's lead of a finding description (owner request, 2026-09-09)."""
from __future__ import annotations

from redsim.services.ml_findings import (
    evasion_plain_language,
    llm_finding_description,
    llm_plain_language,
)


def test_evasion_lead_names_the_technique_the_budget_and_the_share() -> None:
    text = evasion_plain_language(
        attack_id="fgsm", attack_name="FGSM", domain="image", eps=0.03, norm="linf",
        n_clean_correct=180, n_flipped=63, threshold=0.2,
        control_n_correct=178, control_n=200, clean_n_correct=180, clean_n=200,
    )
    assert text.startswith("What happened: redsim took the images this model classified correctly")
    assert "FGSM technique, which adds one small, carefully aimed layer of noise" in text
    assert "ε=0.03 (linf) (small enough that a person would not notice)" in text
    assert "63 of 180 (35%)" in text and "above the 20% rate" in text
    assert "random noise moved accuracy from 180/200 to 178/200" in text
    assert "not a statement about fielded behaviour" in text


def test_evasion_lead_degrades_without_counts_and_for_unknown_attacks() -> None:
    text = evasion_plain_language(
        attack_id="mystery", attack_name="Mystery", domain="tabular", eps=None, norm="l2",
        n_clean_correct=None, n_flipped=None, threshold=0.2,
    )
    assert "records" in text and "the declared budget (l2)" in text
    assert "alters each input in a way chosen to mislead the model" in text
    assert "a share above the reporting threshold" in text
    assert "random noise" not in text


def test_llm_lead_and_description_start_with_the_plain_account() -> None:
    lead = llm_plain_language(probe_id="dan.Dan_11_0", goal="disregard the system prompt", n_hits=4, n_evaluated=16, threshold=0.2)
    assert lead.startswith("What happened: redsim sent this AI model 16 test messages from the 'dan.Dan_11_0' test")
    assert "get it to disregard the system prompt" in lead and "4 of 16 replies (25%)" in lead
    assert "12 of the replies held the line" in lead
    full = llm_finding_description(
        probe_id="dan.Dan_11_0", goal="disregard the system prompt", detector="mitigation.MitigationBypass",
        n_hits=4, n_evaluated=16, n_none=0, hit_rate=0.25, threshold=0.2, severity="medium", model_id="m",
        persona="default", guardrail_mode="off", seed=0, max_prompts=16, garak_version="0.16.0",
    )
    assert full.startswith(lead) and " Measured: garak probe" in full
