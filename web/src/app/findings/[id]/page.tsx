"use client";

import { useState } from "react";
import {
  AuditChainBadge,
  EvidenceDiff,
  FindingCard,
  LabelBadge,
  PanelSection,
  RobustnessCurve,
  RoleGated,
} from "@redsim/design-system";
import {
  ApiError,
  artifactUrl,
  dismissFinding,
  explainFinding,
  hardenFinding,
  verifyFinding,
  type DefenseInfo,
  type CandidateRecommendation,
  type Measurement,
  type Observation,
} from "@/lib/api";
import { useFinding } from "@/hooks/useFinding";
import { useDefenses } from "@/hooks/useMlCatalog";
import { describeFinding } from "@/lib/finding-description";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";

function ArtifactImage({ artifact, alt }: { artifact?: string; alt: string }) {
  const [failed, setFailed] = useState(false);
  if (!artifact || failed)
    return (
      <div
        role="img"
        aria-label={`${alt}; unavailable`}
        className="flex aspect-square items-center justify-center rounded-[3px] bg-ground p-3 text-xs text-ink-3"
      >
        Artifact unavailable
      </div>
    );
  return (
    <img
      src={artifactUrl(artifact)}
      alt={alt}
      onError={() => setFailed(true)}
      className="aspect-square w-full rounded-[3px] bg-ground object-contain"
    />
  );
}

function InputEvidence({ observation }: { observation: Observation }) {
  const tabular = observation.modality === "tabular";
  if (tabular) {
    const clean = observation.feature_values_clean;
    const adv = observation.feature_values_adv;
    if (!clean || !adv) {
      return (
        <p className="border border-dashed border-line-strong p-3 text-sm text-ink-3">
          Recorded feature values are unavailable for this tabular observation.
          Attribution rankings are shown separately and are not input values.
        </p>
      );
    }
    const keys = Array.from(
      new Set([...Object.keys(clean), ...Object.keys(adv)]),
    ).sort();
    return (
      <EvidenceDiff
        aria-label="Tabular evidence difference"
        diff={[
          "--- clean",
          "+++ adversarial",
          ...keys.flatMap((key) => [
            `- ${key}: ${String(clean[key] ?? "not recorded")}`,
            `+ ${key}: ${String(adv[key] ?? "not recorded")}`,
          ]),
        ].join("\n")}
      />
    );
  }
  const artifacts = observation.artifacts;
  return (
    <div className="grid grid-cols-2 gap-2">
      {(["original", "adv", "perturbation", "control"] as const).map((key) => (
        <figure key={key}>
          <ArtifactImage
            artifact={artifacts[key]}
            alt={`${key} evidence for sample ${observation.sample_index}`}
          />
          <figcaption className="mt-1 text-[11px] text-ink-3">
            {key === "control" ? "same-ε control" : key}
          </figcaption>
        </figure>
      ))}
    </div>
  );
}

/** The description as labelled boxes: the plain account first, the measured sections after it. */
function DescriptionBoxes({ description }: { description: string | undefined }) {
  const sections = describeFinding(description);
  if (sections.length === 0) {
    return <p>Measured threshold crossing; inspect the recorded evidence below.</p>;
  }
  return (
    <div className="space-y-4">
      {sections.map((s, i) => (
        <section
          key={`${s.key}-${i}`}
          className={s.plain ? "" : "border-t border-line pt-3 sm:grid sm:grid-cols-[11rem_minmax(0,1fr)] sm:gap-6"}
        >
          <h3 className="redsim-kicker mb-1 text-xs">{s.heading}</h3>
          <p className={s.plain ? "redsim-prose m-0" : "m-0 font-sans text-sm leading-relaxed text-ink-2"}>{s.text}</p>
        </section>
      ))}
    </div>
  );
}

export default function FindingPage({ params }: { params: { id: string } }) {
  const authed = useRequireAuth();
  const { data, error, mutate } = useFinding(authed ? params.id : null);
  const { data: defenses = [] } = useDefenses(authed);
  const { roles } = useRoles();
  const [pending, setPending] = useState<
    "" | "explain" | "harden" | "verify" | "dismiss"
  >("");
  const [feedback, setFeedback] = useState("");
  const [defenseId, setDefenseId] = useState("");
  const [defenseParams, setDefenseParams] = useState("{}");

  if (!authed) return <p>Signing in…</p>;
  if (error) {
    const message =
      error instanceof ApiError
        ? ({
            403: "Access denied for this finding.",
            404: "Finding not found.",
            409: "Finding action conflicts with its current recorded state.",
            501: "This finding capability is not implemented.",
            503: "Finding service unavailable; retry later.",
          }[error.status] ?? `Finding unavailable (${error.status}).`)
        : "Finding unavailable. Retry.";
    return (
      <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
        {message}
      </p>
    );
  }
  if (!data)
    return (
      <div aria-label="Loading finding" className="space-y-3">
        <div className="h-24 animate-pulse rounded-[4px] bg-surface-2" />
        <div className="h-64 animate-pulse rounded-[4px] bg-surface-2" />
      </div>
    );

  const ml = data.schema_blob.ml;
  const role = roles[data.project_id];
  const observation = ml?.observations[0];
  const referenceMeasurement = ml?.measurements.find(
    (row: Measurement) =>
      row.attack_id === ml.attack_id &&
      Number(row.params.eps) === ml.reference_eps,
  );
  const recommendationForDefense = ml?.recommendations.find(
    (recommendation: CandidateRecommendation) =>
      recommendation.references.includes(
        defenses.find((defense: DefenseInfo) => defense.id === defenseId)
          ?.art_class ?? "",
      ),
  );
  const act = async (
    name: typeof pending,
    action: () => Promise<unknown>,
    success: string,
  ) => {
    setPending(name);
    setFeedback("");
    try {
      await action();
      setFeedback(success);
      await mutate();
    } catch (cause) {
      setFeedback(
        cause instanceof ApiError
          ? `${cause.status}: ${cause.message}`
          : String(cause),
      );
    } finally {
      setPending("");
    }
  };
  const parsedParams = () => {
    try {
      return JSON.parse(defenseParams) as Record<string, unknown>;
    } catch {
      throw new Error("Defense parameters must be valid JSON.");
    }
  };
  const curve =
    ml?.measurements
      .filter((row: Measurement) => typeof row.params.eps === "number")
      .map((row: Measurement) => ({
        attack_id: row.attack_id ?? undefined,
        family: row.family,
        eps: Number(row.params.eps),
        accuracy: row.accuracy,
        n: row.n,
        n_correct: row.n_correct,
      })) ?? [];

  return (
    <div className="space-y-5">
      <FindingCard
        id={data.id}
        title={data.schema_blob.title ?? data.id}
        severity={data.severity}
        status={data.status}
        target={data.schema_blob.target}
        validationState={data.validation_state}
        actions={
          <RoleGated minRole="approver" callerRole={role}>
            <button
              onClick={() => {
                const reason = window.prompt("Reason for dismissal");
                if (reason)
                  void act(
                    "dismiss",
                    () => dismissFinding(data.id, reason, data.status),
                    "Dismissal recorded.",
                  );
              }}
              className="redsim-ghost redsim-btn-sm"
            >
              Dismiss
            </button>
          </RoleGated>
        }
      >
        <DescriptionBoxes description={data.schema_blob.description} />
      </FindingCard>
      {feedback && (
        <p
          role="status"
          className="redsim-panel p-3 text-sm text-ink-1"
        >
          {feedback}
        </p>
      )}

      {!ml ? (
        <p className="border border-dashed border-line-strong p-4 text-sm text-ink-3">
          ML evidence unavailable: no canonical schema_blob.ml record.
        </p>
      ) : (
        <div>
          <PanelSection title="Input" eyebrow="pane 01">
            {observation ? (
              <>
                <InputEvidence observation={observation} />
                <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 text-xs [&_dt]:text-xs [&_dt]:font-medium [&_dt]:text-ink-3 [&_dd]:m-0 [&_dd]:mt-0.5 [&_dd]:text-ink-1 sm:grid-cols-4">
                  <div>
                    <dt>Predictions</dt>
                    <dd>
                      {observation.pred_clean} → {observation.pred_adv}{" "}
                      {observation.flipped ? "· flipped" : "· unchanged"}
                    </dd>
                  </div>
                  <div>
                    <dt>Confidence</dt>
                    <dd>
                      {observation.confidence_clean} →{" "}
                      {observation.confidence_adv}
                    </dd>
                  </div>
                  <div>
                    <dt>Measured L∞ / L2</dt>
                    <dd>
                      {observation.linf_norm ?? "not recorded"} /{" "}
                      {observation.l2_norm ?? "not recorded"}
                    </dd>
                  </div>
                  <div>
                    <dt>Control</dt>
                    <dd>
                      {observation.control_pred ?? "not recorded"}{" "}
                      {observation.control_confidence != null
                        ? `· ${observation.control_confidence}`
                        : ""}
                    </dd>
                  </div>
                </dl>
              </>
            ) : (
              <p className="text-sm text-ink-3">
                Input evidence absent: no observation was recorded.
              </p>
            )}
          </PanelSection>

          <PanelSection title="Explanation" eyebrow="pane 02">
            {observation?.artifacts.shap_clean &&
            observation.artifacts.shap_adv ? (
              <div className="grid grid-cols-2 gap-2">
                <ArtifactImage
                  artifact={observation.artifacts.shap_clean}
                  alt={`Clean SHAP attribution for sample ${observation.sample_index}`}
                />
                <ArtifactImage
                  artifact={observation.artifacts.shap_adv}
                  alt={`Adversarial SHAP attribution for sample ${observation.sample_index}`}
                />
              </div>
            ) : (
              <p className="text-sm text-ink-3">
                Explanation absent:{" "}
                {ml.explanation_unavailable_reason ??
                  observation?.explanation_unavailable_reason ??
                  "no SHAP artifact was recorded."}
              </p>
            )}
            {observation && (
              <div className="mt-3 text-xs leading-6 text-ink-2">
                <LabelBadge variant="heuristic" /> center-mass{" "}
                {observation.center_mass_ratio_clean ?? "—"} →{" "}
                {observation.center_mass_ratio_adv ?? "—"}
                <br />
                per-sample explanation shift{" "}
                {observation.expl_shift ?? "not recorded"}
                <br />
                aggregate explanation shift at reference ε{" "}
                {referenceMeasurement?.expl_shift_mean ?? "not recorded"} · n=
                {referenceMeasurement?.expl_shift_n ?? "not recorded"} · noise
                floor{" "}
                {referenceMeasurement?.expl_shift_noise_floor ??
                  "not recorded"}{" "}
                (n=
                {referenceMeasurement?.expl_shift_noise_floor_n ??
                  "not recorded"}
                )
              </div>
            )}
            <p className="redsim-prose mt-3 text-base">
              Attribution describes model sensitivity; it is not causal proof.
            </p>
            {!observation?.artifacts.shap_clean && (
              <RoleGated minRole="scanner" callerRole={role}>
                <button
                  disabled={!!pending}
                  onClick={() =>
                    void act(
                      "explain",
                      () => explainFinding(data.id),
                      "Explanation job accepted (202); evidence remains pending.",
                    )
                  }
                  className="redsim-ghost redsim-btn-sm mt-3"
                >
                  {pending === "explain" ? "Requesting…" : "Explain"}
                </button>
              </RoleGated>
            )}
          </PanelSection>

          <PanelSection title="Candidates" eyebrow="pane 03">
            <div className="space-y-3">
              {ml.recommendations.map(
                (candidate: CandidateRecommendation, index: number) => (
                  <article
                    key={candidate.id}
                    className="border-b border-line pb-3 text-sm last:border-0"
                  >
                    <div className="flex flex-wrap items-baseline justify-between gap-2">
                      <strong className="text-ink-1">
                        {index + 1}. {candidate.title}
                      </strong>
                      <span className="redsim-chip">
                        candidate ·{" "}
                        {candidate.measured ? "measured" : "not evaluated"}
                      </span>
                    </div>
                    <p className="redsim-prose mt-1 text-base">{candidate.rationale}</p>
                    <p className="mt-1 text-xs text-ink-3">
                      trigger: {candidate.triggered_by.join(", ")} · source:{" "}
                      {candidate.narrative_source}
                    </p>
                  </article>
                ),
              )}
            </div>
            <RoleGated minRole="remediator" callerRole={role}>
              <div className="redsim-panel mt-4 space-y-3 p-4">
                <select
                  aria-label="Defense"
                  value={defenseId}
                  onChange={(e) => setDefenseId(e.target.value)}
                  className="redsim-input"
                >
                  <option value="">Select defense</option>
                  {defenses.map((defense: DefenseInfo) => (
                    <option key={defense.id} value={defense.id}>
                      {defense.name}
                    </option>
                  ))}
                </select>
                <label className="redsim-kicker block">
                  Defense parameters
                  <textarea
                    value={defenseParams}
                    onChange={(e) => setDefenseParams(e.target.value)}
                    className="redsim-input font-mono mt-1 min-h-16"
                  />
                </label>
                <div className="flex gap-2">
                  <button
                    disabled={!!pending}
                    onClick={() =>
                      void act(
                        "harden",
                        () => hardenFinding(data.id, { llm_narrative: false }),
                        "Candidate generation accepted; results pending.",
                      )
                    }
                    className="redsim-ghost"
                  >
                    Harden
                  </button>
                  <button
                    disabled={
                      !!pending || !defenseId || !recommendationForDefense
                    }
                    onClick={() => {
                      try {
                        if (!recommendationForDefense) return;
                        const values = parsedParams();
                        void act(
                          "verify",
                          () =>
                            verifyFinding(
                              data.id,
                              defenseId,
                              { ...values },
                              recommendationForDefense.id,
                            ),
                          "Verification accepted; measured results pending.",
                        );
                      } catch (cause) {
                        setFeedback(String(cause));
                      }
                    }}
                    className="redsim-cta"
                  >
                    Verify
                  </button>
                </div>
              </div>
            </RoleGated>
            {ml.verify?.delta && (
              <div className="mt-4 border-t border-line pt-3 text-xs tabular-nums text-ink-2 [&_p]:m-0">
                <strong className="text-ink-1">Recorded measured verification</strong>
                <p>ΔMRI {ml.verify.delta.delta}</p>
                {Object.entries(ml.verify.delta.delta_subscores).map(
                  ([key, value]) => (
                  <p key={key}>
                    {key}: {value ?? "not recorded"}
                  </p>
                ))}
                <p>
                  Clean accuracy{" "}
                  {ml.verify.delta.delta_acc_clean.before.accuracy ??
                    "not recorded"}{" "}
                  (n={ml.verify.delta.delta_acc_clean.before.n}) →{" "}
                  {ml.verify.delta.delta_acc_clean.after.accuracy ??
                    "not recorded"}{" "}
                  (n={ml.verify.delta.delta_acc_clean.after.n})
                </p>
                {ml.verify.delta.delta_families.map((family) => (
                  <p key={family.measurement_id}>
                    {family.measurement_id}{" "}
                    {family.before.accuracy ?? "not recorded"} (n=
                    {family.before.n}) →{" "}
                    {family.after.accuracy ?? "not recorded"} (n=
                    {family.after.n}) · Δ {family.delta ?? "not recorded"}
                  </p>
                ))}
              </div>
            )}
          </PanelSection>
        </div>
      )}

      {ml && (
        <div>
          <PanelSection title="Related robustness" eyebrow="recorded curve">
            <RobustnessCurve points={curve} />
          </PanelSection>
          <PanelSection title="Audit events" eyebrow="recorded chain">
            <AuditChainBadge
              state={ml.audit?.state ?? "pending"}
              events={ml.audit?.events}
              chainId={`run:${data.run_id}`}
            />
            <ul className="m-0 mt-3 list-none p-0 font-mono text-xs text-ink-3">
              {ml.audit?.entries?.map(
                (entry: { id: string; action: string; at: string }) => (
                  <li key={entry.id}>
                    {entry.at} · {entry.action}
                  </li>
                ),
              )}
            </ul>
          </PanelSection>
          <PanelSection title="Campaign" eyebrow="source run">
            <a
              href={`/runs/${data.run_id}`}
              className="redsim-link font-mono text-sm"
            >
              {data.run_id}
            </a>
          </PanelSection>
        </div>
      )}
    </div>
  );
}
