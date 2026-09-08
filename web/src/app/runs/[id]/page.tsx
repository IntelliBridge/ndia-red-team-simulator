"use client";

import { useState } from "react";
import {
  AuditChainBadge,
  LabelBadge,
  MeasurementTable,
  MriScorecard,
  ObservationCard,
  PanelSection,
  RoleGated,
  RobustnessCurve,
  RunStatusBadge,
  StageTimeline,
  type StageEntry,
} from "@redsim/design-system";
import {
  artifactUrl,
  ApiError,
  cancelRun,
  compareRuns,
  dismissFinding,
  isCancellable,
  patchReviewerNotes,
  reportUrl,
  startCampaign,
  verifyFinding,
  type Campaign,
  type Comparison,
  type DefenseInfo,
} from "@/lib/api";
import { useCampaign } from "@/hooks/useCampaign";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { useRoles } from "@/hooks/useRoles";
import { useRunEvents } from "@/hooks/useRunEvents";
import { useDefenses } from "@/hooks/useMlCatalog";

export default function RunPage({ params }: { params: { id: string } }) {
  const authed = useRequireAuth();
  const { data, error, mutate } = useCampaign(authed ? params.id : "");
  const { roles } = useRoles();
  const [stages, setStages] = useState<StageEntry[]>([]);
  const [notes, setNotes] = useState<string | null>(null);
  const [noteError, setNoteError] = useState("");
  const [cancelError, setCancelError] = useState("");
  const [compareId, setCompareId] = useState("");
  const [compareResult, setCompareResult] = useState<Comparison | null>(null);
  const [compareError, setCompareError] = useState("");
  const [actionError, setActionError] = useState("");
  const [defenseSelections, setDefenseSelections] = useState<
    Record<string, string>
  >({});
  const { data: defenses = [] } = useDefenses(authed);
  useRunEvents(authed ? params.id : null, (event) => {
    if (event.type === "job") {
      void mutate();
      return;
    }
    if (!event.name) return;
    const stageName = event.name;
    setStages((current: StageEntry[]) => {
      const next = {
        name: stageName,
        mode: event.status,
        success:
          event.status === "succeeded"
            ? true
            : event.status === "failed"
              ? false
              : null,
      };
      return [
        ...current.filter((stage) => stage.name !== next.name),
        next,
      ];
    });
    void mutate();
  });

  if (!authed) return <p>Redirecting to sign in…</p>;
  if (error)
    return (
      <div className="border border-destructive/40 bg-destructive/10 p-4 text-sm">
        {error instanceof ApiError
          ? ({
              403: "Access denied for this campaign.",
              404: "Campaign not found.",
              409: "Campaign evidence is incompatible.",
              501: "Campaign capability is not implemented.",
              503: "Campaign service unavailable; retry later.",
            }[error.status] ?? `Campaign unavailable (${error.status}).`)
          : "Campaign unavailable. Retry."}
      </div>
    );
  if (!data)
    return (
      <div className="space-y-3">
        <div className="h-8 w-64 animate-pulse bg-muted" />
        <div className="h-40 animate-pulse bg-muted" />
      </div>
    );

  const campaign = data as Campaign;
  const role = roles[campaign.project_id];
  const canAnnotate =
    role === "remediator" || role === "approver" || role === "admin";
  const campaignModality = campaign.config.modality;
  const availableDefenses =
    campaignModality === "llm"
      ? []
      : defenses.filter(
          (defense: DefenseInfo) =>
            defense.status === "available" &&
            defense.modalities.includes(campaignModality),
        );
  const saveNotes = async () => {
    try {
      setNoteError("");
      await patchReviewerNotes(
        params.id,
        notes ?? campaign.reviewer_notes ?? "",
      );
      await mutate();
    } catch (e) {
      setNoteError(String(e));
    }
  };
  const cancel = async () => {
    if (
      !window.confirm(
        "Cancel this run? Recorded partial evidence will be preserved.",
      )
    )
      return;
    try {
      setCancelError("");
      await cancelRun(params.id);
      await mutate();
    } catch (e) {
      setCancelError(String(e));
    }
  };
  const panel = (number: number, title: string, children: React.ReactNode) => (
    <div data-testid={`run-panel-${number}`} key={number}>
      <PanelSection eyebrow={`${number}`.padStart(2, "0")} title={title}>
        {children}
      </PanelSection>
    </div>
  );

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="redsim-kicker">campaign review</div>
          <h1 className="font-mono text-2xl">{params.id}</h1>
          <div className="mt-2">
            <RunStatusBadge status={campaign.status} />
          </div>
        </div>
        <div className="flex items-center gap-3 text-sm">
          {(["html", "json", "md"] as const).map((ext) => (
            <RoleGated key={ext} minRole="scanner" callerRole={role}>
              <a
                className="text-primary underline"
                href={reportUrl(params.id, ext)}
                target="_blank"
                rel="noreferrer"
              >
                {ext.toUpperCase()}
              </a>
            </RoleGated>
          ))}
          {isCancellable(campaign?.status) && (
            <RoleGated minRole="remediator" callerRole={role}>
              <button
                onClick={cancel}
                className="border border-destructive/30 px-3 py-1 text-destructive"
              >
                Cancel run
              </button>
            </RoleGated>
          )}
        </div>
      </header>
      <StageTimeline stages={stages} />
      {cancelError && (
        <p className="border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {cancelError}
        </p>
      )}
      <div className="space-y-4">
        {panel(
          1,
          "Completeness",
          <div>
            <p>
              {campaign.status === "queued" || campaign.status === "running"
                ? "Evidence is still arriving; this page refreshes while active."
                : campaign.status === "succeeded" &&
                    campaign.completeness === "complete"
                  ? "Campaign stages complete."
                  : campaign.status === "succeeded"
                    ? "Campaign finished with partial evidence."
                    : campaign.status === "failed"
                      ? "Campaign failed. Recorded partial evidence is preserved."
                      : "Campaign was cancelled. Recorded partial evidence is preserved."}
            </p>
            <p className="mt-2 text-xs text-muted-foreground">
              {campaign.stages_done.join(" · ") ||
                "No completed stages recorded"}
              {campaign.error ? ` — ${campaign.error}` : ""}
            </p>
          </div>,
        )}
        {panel(
          2,
          "Campaign settings",
          <dl className="grid grid-cols-2 gap-4 text-sm md:grid-cols-3">
            <div>
              <dt className="redsim-kicker">attacks</dt>
              <dd>{campaign.config.attack_ids.join(", ")}</dd>
            </div>
            <div>
              <dt className="redsim-kicker">ε grid</dt>
              <dd>{campaign.config.eps_grid.join(", ")}</dd>
            </div>
            <div>
              <dt className="redsim-kicker">reference ε</dt>
              <dd>{campaign.config.reference_eps}</dd>
            </div>
            <div>
              <dt className="redsim-kicker">samples</dt>
              <dd>{campaign.config.n_samples ?? "not recorded"}</dd>
            </div>
            <div>
              <dt className="redsim-kicker">seed</dt>
              <dd>{campaign.config.seed ?? "not recorded"}</dd>
            </div>
            <div>
              <dt className="redsim-kicker">finding ASR threshold</dt>
              <dd>
                {campaign.config.finding_asr_threshold ?? "not recorded"}
              </dd>
            </div>
            <div>
              <dt className="redsim-kicker">dataset</dt>
              <dd>{campaign.config.dataset_id}</dd>
            </div>
            <div>
              <dt className="redsim-kicker">dataset revision</dt>
              <dd className="break-all">
                {campaign.config.dataset_revision ?? "not recorded"}
              </dd>
            </div>
            <div>
              <dt className="redsim-kicker">control / explain k</dt>
              <dd>
                {campaign.config.include_control ? "enabled" : "disabled"} /{" "}
                {campaign.config.explain_k ?? "not recorded"}
              </dd>
            </div>
            <div>
              <dt className="redsim-kicker">params</dt>
              <dd>
                {Object.entries(campaign.config.attack_params ?? {})
                  .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
                  .join(", ") || "catalog defaults"}
              </dd>
            </div>
            <div>
              <dt className="redsim-kicker">scoring weights</dt>
              <dd>
                {Object.entries(campaign.config.scoring.weights)
                  .map(([key, value]) => `${key}=${value}`)
                  .join(", ")}
              </dd>
            </div>
            <div>
              <dt className="redsim-kicker">settings hash</dt>
              <dd className="break-all">
                {campaign.settings_hash ?? "not recorded"}
              </dd>
            </div>
            <div>
              <dt className="redsim-kicker">framework versions</dt>
              <dd>
                {Object.entries(campaign.target.metadata.framework_versions ?? {})
                  .map(([key, value]) => `${key}=${value}`)
                  .join(", ") || "not recorded"}
              </dd>
            </div>
          </dl>,
        )}
        {panel(
          3,
          "MRI scorecard",
          <MriScorecard
            score={campaign.score}
            familyRows={campaign.measurements.map((row) => ({
              family: row.attack_id ?? row.family,
              accuracy: row.accuracy,
              n: row.n,
            }))}
            measuredDelta={campaign.score?.delta?.delta}
            curve={campaign.curve}
            unavailableReason={
              campaign.score_status?.reason ??
              (campaign.missing.join(", ") ||
                "required evidence is incomplete")
            }
          />,
        )}
        {panel(
          4,
          "Measurements & robustness",
          <div className="grid gap-5 lg:grid-cols-[1.2fr_1fr]">
            <MeasurementTable measurements={campaign.measurements} />
            <RobustnessCurve points={campaign.curve} />
          </div>,
        )}
        {panel(
          5,
          "Observation gallery",
          <div className="grid gap-3 md:grid-cols-2">
            {campaign.observations.map((observation) => (
              <ObservationCard
                key={observation.id}
                observation={observation}
                artifactUrl={artifactUrl}
              />
            ))}
          </div>,
        )}
        {panel(
          6,
          "Interpretation",
          <div className="space-y-3">
            {campaign.interpretation.map((item) => (
              <div
                key={item.id}
                className="border-l-2 border-accent pl-3 text-sm"
              >
                <LabelBadge variant="inferred" />{" "}
                <span className="ml-2">{item.statement}</span>
                <div className="mt-1 text-xs text-muted-foreground">
                  basis:{" "}
                  {item.basis.map((basis) => (
                    <a
                      key={basis}
                      href={`#${basis}`}
                      className="ml-1 text-primary underline"
                    >
                      {basis}
                    </a>
                  ))}
                </div>
              </div>
            ))}
          </div>,
        )}
        {panel(
          7,
          "Candidate actions",
          <div className="space-y-3">
            {campaign.recommendations.map((item) => (
              <div key={item.id} className="border border-border p-3 text-sm">
                <LabelBadge
                  variant={item.measured ? "measured" : "candidate"}
                  measuredDelta={
                    item.measured ? (item.measured.delta_mri ?? null) : undefined
                  }
                />
                <div className="mt-2 font-semibold">{item.title}</div>
                <p className="mt-1">{item.rationale}</p>
                <div className="text-xs text-muted-foreground">
                  triggered by{" "}
                  {item.triggered_by.map((basis) => (
                    <a
                      key={basis}
                      href={`#${basis}`}
                      className="ml-1 text-primary underline"
                    >
                      {basis}
                    </a>
                  ))}{" "}
                  · {item.narrative_source} narrative · {item.validation}
                </div>
                {item.measured && (
                  <p className="mt-1 text-xs">
                    Measured verification ΔMRI {item.measured.delta_mri ?? "—"}{" "}
                    · ΔASR {item.measured.delta_asr ?? "—"}
                  </p>
                )}
                <RoleGated minRole="remediator" callerRole={role}>
                  <select
                    aria-label={`Defense for ${item.title}`}
                    value={defenseSelections[item.id] ?? ""}
                    onChange={(event) =>
                      setDefenseSelections(
                        (current: Record<string, string>) => ({
                          ...current,
                          [item.id]: event.target.value,
                        }),
                      )
                    }
                    className="mt-2 border border-input bg-background p-1"
                  >
                    <option value="">Select defense</option>
                    {availableDefenses.map((defense: DefenseInfo) => (
                      <option key={defense.id} value={defense.id}>
                        {defense.name}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={async () => {
                      if (!item.finding_id) return;
                      try {
                        setActionError("");
                        await verifyFinding(
                          item.finding_id,
                          defenseSelections[item.id] ?? "",
                          {},
                          item.id,
                        );
                        await mutate();
                      } catch (cause) {
                        setActionError(String(cause));
                      }
                    }}
                    disabled={
                      !item.finding_id || !defenseSelections[item.id]
                    }
                    className="ml-2 border border-border px-2 py-1"
                  >
                    Verify
                  </button>
                  {!item.finding_id && (
                    <p className="mt-2 text-xs text-muted-foreground">
                      Verification unavailable: no finding is linked to this
                      recommendation.
                    </p>
                  )}
                </RoleGated>
              </div>
            ))}
          </div>,
        )}
        {panel(
          8,
          "Limitations",
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {(campaign.limitations.length
              ? campaign.limitations
              : ["Limitations were not recorded; evidence is incomplete."]
            ).map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>,
        )}
        {panel(
          9,
          "Provenance",
          <div>
            <dl className="grid grid-cols-2 gap-3 text-sm">
              {Object.entries(campaign.provenance ?? {}).map(([key, value]) => (
                <div key={key}>
                  <dt className="redsim-kicker">{key}</dt>
                  <dd>{String(value)}</dd>
                </div>
              ))}
            </dl>
            <RoleGated minRole="scanner" callerRole={role}>
              <button
                onClick={async () => {
                  const {
                    target_id: _targetId,
                    modality: _modality,
                    dataset_split: _datasetSplit,
                    scoring: _scoring,
                    defense: _defense,
                    target_snapshot: _targetSnapshot,
                    attacks: _attacks,
                    ...request
                  } = campaign.config;
                  const result = await startCampaign(
                    campaign.target.id,
                    request,
                  );
                  window.location.assign(`/runs/${result.run_id}`);
                }}
                className="mt-3 border border-border px-3 py-2 text-sm"
              >
                Rerun same config
              </button>
            </RoleGated>
          </div>,
        )}
        {panel(
          10,
          "Reviewer notes",
          <div>
            <textarea
              aria-label="Reviewer notes"
              value={notes ?? campaign.reviewer_notes ?? ""}
              onChange={(event) => setNotes(event.target.value)}
              readOnly={!canAnnotate}
              aria-readonly={!canAnnotate}
              className="min-h-24 w-full rounded-sm border border-input bg-background p-3 text-sm"
            />
            <RoleGated minRole="remediator" callerRole={role}>
              <button
                onClick={saveNotes}
                className="mt-2 bg-primary px-3 py-2 text-sm text-primary-foreground"
              >
                Save notes
              </button>
            </RoleGated>
            {noteError && (
              <p className="mt-2 text-sm text-destructive">{noteError}</p>
            )}
            {!canAnnotate && (
              <p className="mt-2 text-xs text-muted-foreground">
                Reviewer notes are read-only for this role.
              </p>
            )}
          </div>,
        )}
        {panel(
          11,
          "Findings",
          <table className="w-full text-left text-xs">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Attack</th>
                <th>First ε</th>
                <th>Finding</th>
                <th>Review</th>
              </tr>
            </thead>
            <tbody>
              {campaign.findings?.map((finding) => (
                <tr key={finding.id} className="border-t border-border">
                  <td>{finding.severity}</td>
                  <td>{finding.schema_blob.ml?.attack_id ?? "—"}</td>
                  <td>{finding.schema_blob.ml?.first_success_eps ?? "—"}</td>
                  <td>
                    <a
                      href={`/findings/${finding.id}`}
                      className="text-primary underline"
                    >
                      {finding.schema_blob.title ?? finding.id}
                    </a>
                  </td>
                  <td>
                    <RoleGated minRole="approver" callerRole={role}>
                      <button
                        onClick={async () => {
                          const reason = window.prompt("Reason for dismissal");
                          if (!reason) return;
                          try {
                            setActionError("");
                            await dismissFinding(
                              finding.id,
                              reason,
                              finding.status,
                            );
                            await mutate();
                          } catch (cause) {
                            setActionError(String(cause));
                          }
                        }}
                        className="border border-border px-2 py-1"
                      >
                        Dismiss
                      </button>
                    </RoleGated>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>,
        )}
        {panel(
          12,
          "Compare",
          <div>
            <label className="text-sm">
              Compare with run
              <input
                value={compareId}
                onChange={(event) => setCompareId(event.target.value)}
                className="ml-2 border border-input bg-background p-2"
              />
            </label>
            <button
              disabled={!compareId}
              onClick={async () => {
                try {
                  setCompareError("");
                  const result = await compareRuns(params.id, compareId);
                  setCompareResult(result);
                } catch (e) {
                  setCompareResult(null);
                  setCompareError(String(e));
                }
              }}
              className="ml-2 border border-border px-3 py-2 text-sm"
            >
              Compare
            </button>
            {compareResult?.mode === "verify_delta" && (
              <div className="mt-3 border border-border p-3 text-sm">
                <strong>Measured verify comparison</strong>
                <p>ΔMRI {compareResult.delta_mri ?? "not recorded"}</p>
                {Object.entries(compareResult.delta_dimensions ?? {}).map(
                  ([name, value]) => (
                    <p key={name}>
                      {name}: {value}
                    </p>
                  ),
                )}
                <p>
                  Clean accuracy{" "}
                  {compareResult.delta_acc_clean?.before.accuracy ??
                    "not recorded"}{" "}
                  (n={compareResult.delta_acc_clean?.before.n ?? "—"}) →{" "}
                  {compareResult.delta_acc_clean?.after.accuracy ??
                    "not recorded"}{" "}
                  (n={compareResult.delta_acc_clean?.after.n ?? "—"}) · Δ{" "}
                  {compareResult.delta_acc_clean?.delta ?? "not recorded"}
                </p>
                {!!compareResult.delta_families?.length && (
                  <table className="mt-2 w-full text-left text-xs">
                    <thead>
                      <tr>
                        <th>Family</th>
                        <th>Before</th>
                        <th>After</th>
                      </tr>
                    </thead>
                    <tbody>
                      {compareResult.delta_families.map((family) => (
                        <tr
                          key={family.family}
                          className="border-t border-border"
                        >
                          <td>{family.family}</td>
                          <td>
                            {family.before} (n={family.n_before})
                          </td>
                          <td>
                            {family.after} (n={family.n_after})
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
            {compareResult?.mode === "side_by_side" && (
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                {(compareResult.scorecards ?? []).map((scorecard, index) => (
                  <div key={index} className="border border-border p-3 text-sm">
                    <strong>
                      Scorecard {index + 1}
                      {scorecard.run_id ? ` · ${scorecard.run_id}` : ""}
                    </strong>
                    <MriScorecard
                      score={scorecard}
                      familyRows={scorecard.measurements?.map((row) => ({
                        family: row.attack_id ?? row.family,
                        accuracy: row.accuracy,
                        n: row.n,
                      }))}
                      curve={scorecard.curve}
                      unavailableReason="the comparison response omitted a full scorecard, table, or curve"
                    />
                    {scorecard.measurements?.length ? (
                      <MeasurementTable measurements={scorecard.measurements} />
                    ) : (
                      <p className="mt-2 text-xs text-muted-foreground">
                        Measurement table unavailable.
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
            {compareResult && (
              <div className="mt-3 text-xs">
                <p>
                  Changed variables:{" "}
                  {compareResult.changed_variables.join(", ") || "none"}
                </p>
                <p>
                  Unchanged variables:{" "}
                  {compareResult.unchanged_variables.join(", ") || "none"}
                </p>
                {compareResult.caveats.map((caveat) => (
                  <p key={caveat} className="text-muted-foreground">
                    {caveat}
                  </p>
                ))}
              </div>
            )}
            {compareError && (
              <p className="mt-2 text-sm text-destructive">{compareError}</p>
            )}
            {actionError && (
              <p className="mt-2 text-sm text-destructive">{actionError}</p>
            )}
          </div>,
        )}
        {panel(
          13,
          "Audit chain",
          <AuditChainBadge
            state={campaign.audit?.state ?? "pending"}
            events={campaign.audit?.events}
            chainId={`run:${params.id}`}
          />,
        )}
      </div>
    </div>
  );
}
