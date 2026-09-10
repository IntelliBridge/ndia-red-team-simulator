import "server-only";

import type {
  Campaign,
  CandidateRecommendation,
  Finding,
  Measurement,
  Observation,
} from "@/lib/api";

/**
 * The prompt the finding chat sends to the gateway.
 *
 * Pure functions over the two records the route already fetched with the
 * caller's own credential, so the model sees exactly what the analyst may see
 * and nothing the analyst typed can stand in for a record. The system text
 * carries the reporting rules of `docs/project-brief.md` as instructions:
 * labels kept, denominators quoted, no expected gain before a verify, no
 * readiness wording. It cannot make the model obey them, so the panel keeps
 * its standing caveat and the analyst keeps the evidence panels.
 */

/** Chat roles the gateway accepts. */
export type ChatRole = "system" | "user" | "assistant";

export type ChatMessage = { role: ChatRole; content: string };

/** Characters of serialized context after which the summary is trimmed. */
export const CONTEXT_CHAR_CAP = 60_000;

/** Observations per record in the summary. The panels show the rest. */
export const MAX_OBSERVATIONS = 8;

/** History turns kept, oldest dropped first. */
export const MAX_HISTORY = 30;

export const SYSTEM_PROMPT = [
  "You are the finding assistant inside redsim, the Adversarial ML Red-Team Simulator.",
  "redsim is a non-operational proof of concept that runs on open, unclassified, public data.",
  "You help an analyst read one recorded finding and the campaign record it came from.",
  "",
  "Rules:",
  "1. Answer only from the recorded context below. If the context does not hold the answer, say: The recorded context does not include that. Do not guess and do not invent a number, an id or a result.",
  "2. Keep the recorded labels. A measurement is measured. An interpretation is inferred. A center-of-mass ratio or an explanation shift is heuristic. A recommendation is a candidate and stays not evaluated until a verify campaign measured it.",
  "3. Never state or estimate an expected gain from a recommendation. Only a measured delta from a verify campaign is a gain. Quote it with the before value, the after value and n.",
  "4. Quote a number with its denominator (n and n_correct) and the measurement id it came from. Quote the MRI only together with its grade, its subscores and its weights, and say that it is a per-campaign index for this recorded run only.",
  "5. Do not use readiness, fielding, deployment, certification, accreditation or approval wording about the model or the system. Do not say that the model is safe, secure, hardened or ready.",
  "6. When the context flags fixture or illustrative data, say so in the answer.",
  "7. Be brief. Use plain sentences and short paragraphs. Use dashes for a list. Do not use Markdown headings or tables. Use the finding's own terms: the attack id, eps, the family name.",
].join("\n");

type Json = Record<string, unknown>;

function compactMeasurement(row: Measurement): Json {
  const { eps, ...params } = row.params ?? {};
  const perClass = row.per_class ?? {};
  return {
    id: row.id,
    family: row.family,
    attack_id: row.attack_id ?? null,
    eps: eps ?? null,
    params,
    n: row.n,
    n_correct: row.n_correct,
    accuracy: row.accuracy,
    n_clean_correct: row.n_clean_correct ?? null,
    n_flipped_from_clean: row.n_flipped_from_clean ?? null,
    attack_success_rate: row.attack_success_rate ?? null,
    pert_first_success_mean: row.pert_first_success_mean ?? null,
    conf_gap_mean: row.conf_gap_mean ?? null,
    expl_shift_mean: row.expl_shift_mean ?? null,
    expl_shift_n: row.expl_shift_n ?? null,
    expl_shift_noise_floor: row.expl_shift_noise_floor ?? null,
    queries_mean: row.queries_mean ?? null,
    per_class: Object.keys(perClass).length <= 16 ? perClass : { classes: Object.keys(perClass).length },
    notes: row.notes ?? [],
  };
}

function compactObservation(row: Observation): Json {
  return {
    id: row.id,
    sample_index: row.sample_index,
    modality: row.modality ?? null,
    true_label: row.true_label,
    pred_clean: row.pred_clean,
    pred_adv: row.pred_adv,
    flipped: row.flipped,
    confidence_clean: row.confidence_clean,
    confidence_adv: row.confidence_adv,
    control_pred: row.control_pred ?? null,
    control_confidence: row.control_confidence ?? null,
    linf_norm: row.linf_norm ?? null,
    l2_norm: row.l2_norm ?? null,
    expl_shift: row.expl_shift ?? null,
    center_mass_ratio_clean: row.center_mass_ratio_clean ?? null,
    center_mass_ratio_adv: row.center_mass_ratio_adv ?? null,
    top_features_clean: row.top_features_clean ?? null,
    top_features_adv: row.top_features_adv ?? null,
    metric_kind: row.metric_kind,
    metric_note: row.metric_note,
    explanation_unavailable_reason: row.explanation_unavailable_reason ?? null,
  };
}

function compactRecommendation(row: CandidateRecommendation): Json {
  return {
    id: row.id,
    title: row.title,
    rationale: row.rationale,
    status: row.status,
    triggered_by: row.triggered_by,
    references: row.references,
    narrative_source: row.narrative_source,
    narrative: row.narrative ?? null,
  };
}

/** The finding as the model should see it: the record minus artifact ids and raw feature dumps. */
export function findingSummary(finding: Finding): Json {
  const blob = finding.schema_blob ?? {};
  const ml = blob.ml ?? null;
  return {
    id: finding.id,
    run_id: finding.run_id,
    project_id: finding.project_id,
    severity: finding.severity,
    status: finding.status,
    source_tool: finding.source_tool ?? null,
    title: blob.title ?? null,
    description: blob.description ?? null,
    target: blob.target ?? null,
    attack_id: blob.attack_id ?? ml?.attack_id ?? null,
    llm: blob.llm ?? null,
    ml: ml
      ? {
          attack_id: ml.attack_id,
          attack_name: ml.attack_name,
          family: ml.family,
          norm: ml.norm,
          eps_grid: ml.eps_grid,
          reference_eps: ml.reference_eps,
          first_success_eps: ml.first_success_eps,
          asr_at_reference: ml.asr_at_reference,
          asr_by_eps: ml.asr_by_eps,
          threshold: ml.threshold,
          measurements: (ml.measurements ?? []).map(compactMeasurement),
          observations: (ml.observations ?? []).slice(0, MAX_OBSERVATIONS).map(compactObservation),
          observations_total: (ml.observations ?? []).length,
          interpretation: ml.interpretation ?? [],
          recommendations: (ml.recommendations ?? []).map(compactRecommendation),
          limitations: ml.limitations ?? [],
          review: ml.review ?? null,
          explanation_unavailable_reason: ml.explanation_unavailable_reason ?? null,
          audit: ml.audit ? { state: ml.audit.state, events: ml.audit.events ?? null } : null,
        }
      : null,
  };
}

/** The campaign summary: score with its subscores, the per-family table, the curve, the config. */
export function campaignSummary(campaign: Campaign): Json {
  const config = campaign.config ?? ({} as Campaign["config"]);
  const score = campaign.score ?? null;
  return {
    run_id: campaign.run_id,
    status: campaign.status,
    completeness: campaign.completeness ?? null,
    missing: campaign.missing ?? [],
    settings_hash: campaign.settings_hash ?? null,
    target: campaign.target
      ? {
          id: campaign.target.id,
          name: campaign.target.name,
          domain: campaign.target.domain,
          status: campaign.target.status,
          reason: campaign.target.reason ?? null,
          metadata: campaign.target.metadata ?? null,
        }
      : null,
    config: {
      modality: config.modality ?? null,
      attacks: (config as { attacks?: unknown }).attacks ?? null,
      attack_ids: (config as { attack_ids?: unknown }).attack_ids ?? null,
      eps_grid: (config as { eps_grid?: unknown }).eps_grid ?? null,
      reference_eps: (config as { reference_eps?: unknown }).reference_eps ?? null,
      n_samples: (config as { n_samples?: unknown }).n_samples ?? null,
      seed: (config as { seed?: unknown }).seed ?? null,
      norm: (config as { norm?: unknown }).norm ?? null,
      dataset_split: config.dataset_split ?? null,
      scoring: config.scoring ?? null,
    },
    score: score
      ? {
          mri: score.mri ?? null,
          grade: score.grade ?? null,
          subscores: score.subscores ?? null,
          weights: score.weights ?? null,
          per_attack: score.per_attack ?? null,
          reading: score.reading ?? null,
          reference_eps: score.reference_eps ?? null,
          eps_grid: score.eps_grid ?? null,
          attack_ids: score.attack_ids ?? null,
        }
      : null,
    score_status: campaign.score_status ?? null,
    curve: (campaign.curve ?? []).map((series) => ({
      attack_id: series.attack_id,
      norm: series.norm,
      reference_eps: series.reference_eps,
      clean: series.clean,
      points: series.points,
      control: series.control,
    })),
    measurements: (campaign.measurements ?? []).map(compactMeasurement),
    observations: (campaign.observations ?? []).slice(0, MAX_OBSERVATIONS).map(compactObservation),
    observations_total: (campaign.observations ?? []).length,
    interpretation: campaign.interpretation ?? [],
    recommendations: (campaign.recommendations ?? []).map(compactRecommendation),
    limitations: campaign.limitations ?? [],
    reviewer_notes: campaign.reviewer_notes ?? null,
    audit: campaign.audit ?? null,
  };
}

export type ContextInput = {
  finding: Finding;
  campaign: Campaign | null;
  /** Why the campaign record is absent, when it is (an upstream code). */
  campaignUnavailable?: string | null;
};

/**
 * Serialize the recorded context, trimming the largest optional blocks first
 * when it exceeds the cap. The trims are recorded in the text so the model
 * can say what it was not shown.
 */
export function serializeContext(input: ContextInput): string {
  const finding = findingSummary(input.finding);
  const campaign = input.campaign ? campaignSummary(input.campaign) : null;
  const doc: Json = {
    finding,
    campaign,
    campaign_unavailable: input.campaignUnavailable ?? null,
    trimmed: [] as string[],
  };
  const trimmed = doc.trimmed as string[];
  const trims: Array<() => void> = [
    () => {
      if (campaign) {
        campaign.observations = [];
        trimmed.push("campaign.observations");
      }
    },
    () => {
      if (campaign) {
        campaign.measurements = (campaign.measurements as Json[]).map((row) => ({
          ...row,
          per_class: undefined,
        }));
        trimmed.push("campaign.measurements.per_class");
      }
    },
    () => {
      const ml = finding.ml as Json | null;
      if (ml) {
        ml.observations = (ml.observations as Json[]).slice(0, 3);
        trimmed.push("finding.ml.observations beyond 3");
      }
    },
    () => {
      if (campaign) {
        campaign.curve = [];
        trimmed.push("campaign.curve");
      }
    },
    () => {
      if (campaign) {
        const rows = campaign.measurements as Json[];
        campaign.measurements = rows.slice(0, 24);
        campaign.measurements_total = rows.length;
        trimmed.push("campaign.measurements beyond 24");
      }
    },
    () => {
      const ml = finding.ml as Json | null;
      if (ml) {
        ml.observations = [];
        trimmed.push("finding.ml.observations");
      }
    },
    () => {
      if (campaign) {
        campaign.measurements = [];
        trimmed.push("campaign.measurements");
      }
    },
  ];
  let text = JSON.stringify(doc);
  for (const trim of trims) {
    if (text.length <= CONTEXT_CHAR_CAP) break;
    trim();
    text = JSON.stringify(doc);
  }
  if (text.length > CONTEXT_CHAR_CAP) {
    // Only a finding record that is itself larger than the cap gets here. The
    // cut is plain text, so the note is appended outside the JSON.
    const note = "\n[context truncated at the character cap]";
    text = `${text.slice(0, CONTEXT_CHAR_CAP - note.length)}${note}`;
  }
  return text;
}

/** A turn as the browser sends it. The route validates the shape before this runs. */
export type HistoryTurn = { role: "user" | "assistant"; content: string };

/**
 * The full message list for one gateway call.
 *
 * One system message carries the rules and the context together, because an
 * OpenAI-compatible gateway in front of an Anthropic model folds every
 * system message into one and the order of the two would be its choice
 * rather than ours. Empty turns are dropped and the history is capped.
 */
export function buildMessages(input: ContextInput, history: HistoryTurn[]): ChatMessage[] {
  const context = serializeContext(input);
  const system: ChatMessage = {
    role: "system",
    content: `${SYSTEM_PROMPT}\n\nRecorded context (JSON):\n${context}`,
  };
  const turns = history
    .filter((turn) => turn.content.trim().length > 0)
    .slice(-MAX_HISTORY)
    .map((turn) => ({ role: turn.role, content: turn.content }));
  return [system, ...turns];
}
