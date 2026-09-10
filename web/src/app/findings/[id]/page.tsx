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
import { FindingChatPanel } from "@/components/finding-chat-panel";
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
        className="flex aspect-square items-center justify-center bg-muted p-3 text-xs text-muted-foreground"
      >
        Artifact unavailable
      </div>
    );
  return (
    <img
      src={artifactUrl(artifact)}
      alt={alt}
      onError={() => setFailed(true)}
      className="aspect-square w-full object-contain bg-muted"
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
        <p className="border border-dashed border-border p-3 text-sm text-muted-foreground">
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
          <figcaption className="mt-1 text-[10px] uppercase tracking-wider">
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
    <div className="grid gap-3 sm:grid-cols-2">
      {sections.map((s, i) => (
        <section
          key={`${s.key}-${i}`}
          className={
            s.plain
              ? "rounded-md border border-primary/30 bg-primary/5 p-3 sm:col-span-2"
              : "rounded-md border border-border bg-card p-3"
          }
        >
          <h3 className="redsim-kicker mb-1 text-xs uppercase tracking-wide text-muted-foreground">{s.heading}</h3>
          <p className={s.plain ? "text-sm leading-relaxed" : "text-xs leading-relaxed text-muted-foreground"}>{s.text}</p>
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
  const [chatOpen, setChatOpen] = useState(false);

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
      <p className="border border-destructive/40 bg-destructive/10 p-4 text-sm">
        {message}
      </p>
    );
  }
  if (!data)
    return (
      <div aria-label="Loading finding" className="space-y-3">
        <div className="h-24 animate-pulse bg-muted" />
        <div className="h-64 animate-pulse bg-muted" />
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
        validationState={data.validation_state ?? null}
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setChatOpen(true)}
              aria-haspopup="dialog"
              aria-expanded={chatOpen}
              className="border border-primary/50 px-2 py-1 text-xs text-primary hover:bg-primary/10"
            >
              Chat
            </button>
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
                className="border border-border px-2 py-1 text-xs"
              >
                Dismiss
              </button>
            </RoleGated>
          </div>
        }
      >
        <DescriptionBoxes description={data.schema_blob.description} />
      </FindingCard>
      <FindingChatPanel finding={data} open={chatOpen} onOpenChange={setChatOpen} />
      {feedback && (
        <p
          role="status"
          className="border border-primary/30 bg-primary/5 p-3 text-sm"
        >
          {feedback}
        </p>
      )}

      {!ml ? (
        <p className="border border-dashed border-border p-4 text-sm">
          ML evidence unavailable: no canonical schema_blob.ml record.
        </p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          <PanelSection title="Input" eyebrow="pane 01">
            {observation ? (
              <>
                <InputEvidence observation={observation} />
                <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
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
              <p className="text-sm text-muted-foreground">
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
              <p className="text-sm text-muted-foreground">
                Explanation absent:{" "}
                {ml.explanation_unavailable_reason ??
                  observation?.explanation_unavailable_reason ??
                  "no SHAP artifact was recorded."}
              </p>
            )}
            {observation && (
              <div className="mt-3 text-xs">
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
            <p className="mt-3 text-sm">
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
                  className="mt-3 border border-border px-3 py-2 text-sm"
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
                    className="border border-border p-3 text-sm"
                  >
                    <div className="flex justify-between">
                      <strong>
                        {index + 1}. {candidate.title}
                      </strong>
                      <span>
                        candidate ·{" "}
                        {candidate.measured ? "measured" : "not evaluated"}
                      </span>
                    </div>
                    <p className="mt-1">{candidate.rationale}</p>
                    <p className="text-xs text-muted-foreground">
                      trigger: {candidate.triggered_by.join(", ")} · source:{" "}
                      {candidate.narrative_source}
                    </p>
                  </article>
                ),
              )}
            </div>
            <RoleGated minRole="remediator" callerRole={role}>
              <div className="mt-4 space-y-2">
                <select
                  aria-label="Defense"
                  value={defenseId}
                  onChange={(e) => setDefenseId(e.target.value)}
                  className="w-full border border-input bg-background p-2"
                >
                  <option value="">Select defense</option>
                  {defenses.map((defense: DefenseInfo) => (
                    <option key={defense.id} value={defense.id}>
                      {defense.name}
                    </option>
                  ))}
                </select>
                <label className="block text-xs">
                  Defense parameters
                  <textarea
                    value={defenseParams}
                    onChange={(e) => setDefenseParams(e.target.value)}
                    className="mt-1 min-h-16 w-full border border-input bg-background p-2 font-mono"
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
                    className="border border-border px-3 py-2"
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
                    className="bg-primary px-3 py-2 text-primary-foreground"
                  >
                    Verify
                  </button>
                </div>
              </div>
            </RoleGated>
            {ml.verify?.delta && (
              <div className="mt-4 border-t border-border pt-3 text-xs">
                <strong>Recorded measured verification</strong>
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
        <div className="grid gap-4 lg:grid-cols-3">
          <PanelSection title="Related robustness" eyebrow="recorded curve">
            <RobustnessCurve points={curve} />
          </PanelSection>
          <PanelSection title="Audit events" eyebrow="recorded chain">
            <AuditChainBadge
              state={ml.audit?.state ?? "pending"}
              events={ml.audit?.events}
              chainId={`run:${data.run_id}`}
            />
            <ul className="mt-3 text-xs">
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
              className="font-mono text-primary underline"
            >
              {data.run_id}
            </a>
          </PanelSection>
        </div>
      )}
    </div>
  );
}
