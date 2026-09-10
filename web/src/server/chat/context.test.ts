// @vitest-environment node
import { describe, expect, it } from "vitest";

import campaignFixture from "@/__fixtures__/campaign.json";
import findingFixture from "@/__fixtures__/finding.json";
import type { AttackInfo, Campaign, Finding, Observation } from "@/lib/api";

import {
  buildMessages,
  campaignSummary,
  CONTEXT_CHAR_CAP,
  findingSummary,
  MAX_HISTORY,
  serializeContext,
  SYSTEM_PROMPT,
} from "./context";

const finding = findingFixture as unknown as Finding;
const campaign = campaignFixture as unknown as Campaign;

describe("finding chat context", () => {
  it("keeps the measurements with their denominators and drops artifact ids", () => {
    const summary = findingSummary(finding);
    const ml = summary.ml as { measurements: Array<Record<string, unknown>>; observations: Array<Record<string, unknown>> };
    expect(ml.measurements[0]).toMatchObject({ id: "m1", family: "evasion", attack_id: "fgsm", eps: 0.03, n: 50, n_correct: 24 });
    expect(ml.observations[0]).not.toHaveProperty("artifacts");
    expect(ml.observations[0]).not.toHaveProperty("artifact_sha256");
    expect(ml.observations[0]).toHaveProperty("metric_kind", "heuristic");
  });

  it("carries the score with its subscores and weights, never the MRI alone", () => {
    const summary = campaignSummary(campaign);
    const score = summary.score as Record<string, unknown>;
    expect(score.mri).toBe(0.58);
    expect(score.grade).toBe("C");
    expect(score.subscores).toMatchObject({ S_acc: 0.82, S_asr: 0.59 });
    expect(score.weights).toMatchObject({ acc: 0.35 });
    expect(summary.curve).toBeInstanceOf(Array);
  });

  it("records why the campaign is absent when it is", () => {
    const text = serializeContext({ finding, campaign: null, campaignUnavailable: "llm_target_required" });
    const doc = JSON.parse(text) as { campaign: unknown; campaign_unavailable: string };
    expect(doc.campaign).toBeNull();
    expect(doc.campaign_unavailable).toBe("llm_target_required");
  });

  it("trims the largest blocks first and stays under the cap", () => {
    const observation = campaign.observations[0] as Observation;
    const bloated: Campaign = {
      ...campaign,
      observations: Array.from({ length: 4000 }, (_, i) => ({
        ...observation,
        id: `o${i}`,
        metric_note: "x".repeat(200),
      })),
      measurements: Array.from({ length: 400 }, (_, i) => ({
        ...campaign.measurements[0]!,
        id: `m${i}`,
        per_class: Object.fromEntries(Array.from({ length: 12 }, (__, c) => [`class_${c}`, { n: 10, n_correct: 5 }])),
        notes: ["y".repeat(120)],
      })),
    };
    const text = serializeContext({ finding, campaign: bloated });
    expect(text.length).toBeLessThanOrEqual(CONTEXT_CHAR_CAP);
    const doc = JSON.parse(text) as { trimmed: string[] };
    expect(doc.trimmed).toContain("campaign.observations");
  });

  it("puts the rules and the context in one system message and caps the history", () => {
    const history = Array.from({ length: MAX_HISTORY + 6 }, (_, i) => ({
      role: (i % 2 === 0 ? "user" : "assistant") as "user" | "assistant",
      content: `turn ${i}`,
    }));
    const messages = buildMessages({ finding, campaign }, history);
    expect(messages[0]?.role).toBe("system");
    expect(messages[0]?.content.startsWith(SYSTEM_PROMPT)).toBe(true);
    expect(messages[0]?.content).toContain('"id":"m1"');
    expect(messages).toHaveLength(1 + MAX_HISTORY);
    expect(messages[messages.length - 1]?.content).toBe(`turn ${MAX_HISTORY + 5}`);
    expect(messages.filter((m) => m.role === "system")).toHaveLength(1);
  });

  it("states the reporting rules the brief imposes", () => {
    for (const phrase of ["expected gain", "denominator", "readiness", "candidate", "not evaluated", "Do not guess"]) {
      expect(SYSTEM_PROMPT).toContain(phrase);
    }
  });

  it("bounds a proposal to the attack roster and keeps the analyst as the one who approves", () => {
    for (const phrase of ["redsim-proposal", "available_attacks", "approves it", "requires_gradients is false", "Never say what the proposed campaign will find"]) {
      expect(SYSTEM_PROMPT).toContain(phrase);
    }
  });

  it("puts the attack roster in the context as ids and flags, never the params schema", () => {
    const attacks = [
      {
        id: "hopskipjump", name: "HopSkipJump", domain: "image", family: "evasion", description: "x",
        params_schema: [{ name: "max_iter" }], references: ["r"], phase: "A", access: "black-box",
        requires_gradients: false, status: "available", capabilities: ["modality:image", "norm:linf", "norm:l2"],
      },
    ] as unknown as AttackInfo[];
    const doc = JSON.parse(serializeContext({ finding, campaign, attacks })) as { available_attacks: Array<Record<string, unknown>> };
    expect(doc.available_attacks).toEqual([
      { id: "hopskipjump", name: "HopSkipJump", family: "evasion", access: "black-box", requires_gradients: false, status: "available", reason: null, norms: ["linf", "l2"] },
    ]);
    expect(JSON.stringify(doc)).not.toContain("params_schema");
    const without = JSON.parse(serializeContext({ finding, campaign })) as { available_attacks: unknown };
    expect(without.available_attacks).toBeNull();
  });
});
