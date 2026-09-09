import { describe, expect, it } from "vitest";

import { describeFinding, findingLead } from "./finding-description";

const EVASION =
  "What happened: redsim took the images this model classified correctly and altered each one with the FGSM technique. " +
  "Measured: FGSM (fgsm, linf) first crossed the finding threshold (ASR >= 0.2) at eps=0.03, flipping 63/180 clean-correct samples [m-1]. " +
  "At the reference budget eps=0.03 the attack success rate was 0.3500 (63/180) and accuracy 117/200 [m-1]. " +
  "Clean accuracy 180/200 [m-0]. Benign noise control at eps=0.03: accuracy 178/200 [m-2]. " +
  "Slice: n=200, seed=0; confidence high from 180 clean-correct samples. Measured at these settings only.";

const LLM =
  "What happened: redsim sent this AI model 5 test messages from the 'dan.DanInTheWild' test, each written to get it to disregard the system prompt. " +
  "Measured: garak probe dan.DanInTheWild (disregard the system prompt) fired detector mitigation.MitigationBypass on 5/5 evaluated responses (hit rate 1.0000), crossing the finding threshold 0.2. " +
  "0 response(s) could not be evaluated by the detector and are outside the denominator. " +
  "Severity high is derived from the hit rate bands (>=0.5 high, >=0.2 medium, >0 low), not from the spec 15.5 ASR bands; a hit means the detector fired, not a verified harm. " +
  "Target: model gpt behind persona default with guardrail_mode off; seed 0, prompt cap 16 per probe, one generation per prompt, garak 0.16.0. Measured at these settings only. " +
  "Prompts and responses are stored in the run's garak report artifacts and are not rendered here.";

describe("describeFinding", () => {
  it("splits an evasion description into its labelled boxes", () => {
    const sections = describeFinding(EVASION);
    expect(sections.map((s) => s.heading)).toEqual([
      "What happened",
      "Measured result",
      "At the reference budget",
      "Clean accuracy",
      "Noise control",
      "Test slice and confidence",
    ]);
    expect(sections[0]!.plain).toBe(true);
    expect(sections[0]!.text.startsWith("redsim took the images")).toBe(true);
    expect(sections[1]!.text.startsWith("FGSM (fgsm, linf) first crossed")).toBe(true);
    expect(sections[5]!.text).toContain("Measured at these settings only.");
  });

  it("splits an LLM probe description and keeps the continuation sentences with their section", () => {
    const sections = describeFinding(LLM);
    expect(sections.map((s) => s.heading)).toEqual([
      "What happened",
      "Measured result",
      "Not evaluated",
      "How severity was set",
      "Target and settings",
      "Evidence",
    ]);
    expect(sections[4]!.text).toContain("Measured at these settings only.");
  });

  it("keeps unknown text as Details and handles empty input", () => {
    expect(describeFinding("")).toEqual([]);
    expect(describeFinding(undefined)).toEqual([]);
    const legacy = describeFinding("Something the old projector wrote.");
    expect(legacy).toEqual([{ key: "details", heading: "Details", text: "Something the old projector wrote.", plain: false }]);
  });

  it("findingLead returns the plain lead alone, trimmed", () => {
    expect(findingLead(EVASION)).toBe(
      "redsim took the images this model classified correctly and altered each one with the FGSM technique.",
    );
    expect(findingLead("Measured: only technical text.")).toBeNull();
    expect(findingLead(LLM, 40)?.endsWith("...")).toBe(true);
  });
});
