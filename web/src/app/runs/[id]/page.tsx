"use client";

import { useState } from "react";
import useSWR from "swr";
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
  SeverityChip,
  StageTimeline,
  type StageEntry,
} from "@redsim/design-system";
import {
  api,
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
  type ArtifactRow,
  type Campaign,
  type Comparison,
  type DefenseInfo,
  type Finding,
  type RunDetail,
} from "@/lib/api";
import { useCampaign } from "@/hooks/useCampaign";
import { useLlmScorecard } from "@/hooks/useLlm";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { rowLink } from "@/lib/row-link";
import { useRoles } from "@/hooks/useRoles";
import { useRunEvents } from "@/hooks/useRunEvents";
import { useDefenses } from "@/hooks/useMlCatalog";
import { LlmScorecardPanel } from "./llm-scorecard";

// Run.scanner / stage_table.kind of a garak probe run (redsim/services/ml_llm.py
// LLM_SCANNER / LLM_RUN_KIND). Such a run has no campaign record: /campaign
// answers 404 campaign_not_found (or 409 llm_target_required), so the page
// falls back to GET /v1/runs/{id} to learn what kind of run it is.
const LLM_SCANNER = "ml.llm_probe";
const LLM_RUN_KIND = "llm_probe";
const ACTIVE_RUN = new Set(["queued", "running"]);
const REPORT_KIND_PREFIX = "ml.report_";

export default function RunPage({ params }: { params: { id: string } }) {
  const authed = useRequireAuth();
  const { data, error, mutate } = useCampaign(authed ? params.id : "");
  const { roles } = useRoles();
  const campaignMissing =
    error instanceof ApiError && (error.status === 404 || error.status === 409);
  const { data: runDetail, error: runError } = useSWR<RunDetail>(
    authed && campaignMissing
      ? `/v1/runs/${encodeURIComponent(params.id)}`
      : null,
    (p: string) => api<RunDetail>(p),
    {
      refreshInterval: (run?: RunDetail) =>
        run?.status && ACTIVE_RUN.has(run.status) ? 5000 : 0,
    },
  );
  const isLlmRun =
    data?.config?.modality === "llm" ||
    runDetail?.scanner === LLM_SCANNER ||
    runDetail?.stage_table?.kind === LLM_RUN_KIND;
  const runStatus = data?.status ?? runDetail?.status ?? null;
  const llmActive = !runStatus || ACTIVE_RUN.has(runStatus);
  const llm = useLlmScorecard(authed && isLlmRun ? params.id : null, {
    // Poll while the run is active; on a terminal run without a scorecard
    // there is nothing to wait for (job events still revalidate below).
    refreshInterval: llmActive ? 5000 : 0,
  });
  const { data: llmArtifacts, mutate: mutateArtifacts } = useSWR<{
    artifacts: ArtifactRow[];
    count: number;
  }>(
    authed && isLlmRun
      ? `/v1/runs/${encodeURIComponent(params.id)}/artifacts`
      : null,
    (p: string) => api<{ artifacts: ArtifactRow[]; count: number }>(p),
    { refreshInterval: llmActive ? 10000 : 0 },
  );
  const { data: llmFindings, mutate: mutateFindings } = useSWR<{
    findings: Finding[];
    count: number;
  }>(
    authed && isLlmRun && !data
      ? `/v1/findings?run=${encodeURIComponent(params.id)}`
      : null,
    (p: string) => api<{ findings: Finding[]; count: number }>(p),
    { refreshInterval: llmActive ? 10000 : 0 },
  );
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
      if (isLlmRun) {
        void llm.mutate();
        void mutateArtifacts();
        void mutateFindings();
      }
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
      return [...current.filter((stage) => stage.name !== next.name), next];
    });
    void mutate();
  });

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

  if (!authed) return <p>Signing in…</p>;

  if (isLlmRun) {
    // An LLM probe run: k/n scorecard, never an MRI (spec 15.9, D9). The
    // campaign-only panels (MRI, eps curve, defenses, compare) do not apply.
    const projectId = data?.project_id ?? runDetail?.project_id ?? "";
    const llmRole = roles[projectId];
    const stageTable = (runDetail?.stage_table ?? {}) as Record<
      string,
      unknown
    >;
    const stagesDone = Array.isArray(stageTable.stages_done)
      ? (stageTable.stages_done as unknown[]).map(String)
      : (data?.stages_done ?? []);
    const stageError =
      (typeof stageTable.error === "string" ? stageTable.error : null) ??
      data?.error ??
      null;
    const probeIds = Array.isArray(stageTable.probe_ids)
      ? (stageTable.probe_ids as unknown[]).map(String)
      : [];
    const artifacts = llmArtifacts?.artifacts ?? [];
    const hasReport = artifacts.some((row) =>
      String(row.kind ?? "").startsWith(REPORT_KIND_PREFIX),
    );
    const findings = data?.findings ?? llmFindings?.findings ?? [];
    return (
      <div className="space-y-6">
        <header className="flex flex-wrap items-end justify-between gap-4 pb-2">
          <div className="min-w-0">
            <div className="redsim-kicker">LLM probe review</div>
            <div className="mt-1 flex flex-wrap items-center gap-4">
              <h1 className="m-0 font-mono text-[1.375rem] font-medium tracking-normal">{params.id}</h1>
              <RunStatusBadge status={runStatus ?? "queued"} />
              <AuditChainBadge
                state={data?.audit?.state ?? "pending"}
                events={data?.audit?.events}
                chainId={`run:${params.id}`}
              />
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs font-medium">
            {hasReport &&
              (["html", "json", "md"] as const).map((ext) => (
                <RoleGated key={ext} minRole="scanner" callerRole={llmRole}>
                  <a
                    className="redsim-link"
                    href={reportUrl(params.id, ext)}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {ext.toUpperCase()}
                  </a>
                </RoleGated>
              ))}
            {isCancellable(runStatus) && (
              <RoleGated minRole="remediator" callerRole={llmRole}>
                <button
                  onClick={cancel}
                  className="redsim-ghost redsim-btn-sm border-destructive/40 text-destructive"
                >
                  Cancel run
                </button>
              </RoleGated>
            )}
          </div>
        </header>
        <StageTimeline stages={stages} />
        {cancelError && (
          <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
            {cancelError}
          </p>
        )}
        <div>
          {panel(
            1,
            "Run status",
            <div>
              <p className="redsim-prose m-0 text-base">
                {runStatus === "queued"
                  ? "Probe run is queued; the worker has not started it yet."
                  : runStatus === "running"
                    ? "Probe run in progress; this page refreshes while active."
                    : runStatus === "succeeded"
                      ? "Probe run complete; the k/n scorecard is below."
                      : runStatus === "failed"
                        ? "Probe run failed. Recorded partial artifacts are preserved."
                        : runStatus === "cancelled"
                          ? "Probe run was cancelled. Recorded partial artifacts are preserved."
                          : runError
                            ? "Run status unavailable."
                            : "Resolving run status…"}
              </p>
              <p className="mt-2 text-xs text-ink-3">
                {stagesDone.join(" · ") || "No completed stages recorded"}
                {stageError ? ` — ${stageError}` : ""}
              </p>
              {probeIds.length > 0 && (
                <p className="mt-2 text-xs text-ink-3">
                  {probeIds.length} probes requested: {probeIds.join(", ")}
                </p>
              )}
              {runDetail?.completed_at && (
                <p className="mt-1 text-xs text-ink-3">
                  completed {runDetail.completed_at}
                </p>
              )}
            </div>,
          )}
          {panel(
            2,
            "LLM probe scorecard",
            <LlmScorecardPanel
              response={llm.data}
              ready={llm.ready}
              error={llm.error}
              runStatus={runStatus}
              runError={stageError}
            />,
          )}
          {panel(
            3,
            "Artifacts",
            artifacts.length ? (
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-line-strong">
                    <th className="px-3 py-2.5 font-medium">Kind</th>
                    <th className="px-3 py-2.5 font-medium">Size</th>
                    <th className="px-3 py-2.5 font-medium">sha256</th>
                    <th className="px-3 py-2.5 font-medium">Artifact</th>
                  </tr>
                </thead>
                <tbody>
                  {artifacts.map((row) => (
                    <tr key={row.id} className="border-b border-line last:border-0">
                      <td className="px-3 py-2.5 font-mono text-xs">{row.kind ?? "—"}</td>
                      <td className="px-3 py-2.5 tabular-nums">
                        {typeof row.size_bytes === "number"
                          ? `${row.size_bytes} B`
                          : "—"}
                      </td>
                      <td className="break-all px-3 py-2.5 font-mono text-xs text-ink-3">
                        {row.sha256 ? row.sha256.slice(0, 16) : "—"}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-xs">
                        <a
                          href={artifactUrl(row.id)}
                          target="_blank"
                          rel="noreferrer"
                          className="redsim-link"
                        >
                          {row.id}
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-sm text-ink-3">
                {llmActive
                  ? "No artifacts yet; they are written as the probe run progresses."
                  : "No artifacts were recorded for this run."}
              </p>
            ),
          )}
          {panel(
            4,
            "Findings",
            findings.length ? (
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-line-strong">
                    <th className="px-3 py-2.5 font-medium">Severity</th>
                    <th className="px-3 py-2.5 font-medium">Status</th>
                    <th className="px-3 py-2.5 font-medium">Finding</th>
                    <th className="px-3 py-2.5 font-medium">Review</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.id} {...rowLink(`/findings/${finding.id}`)} className={`border-b border-line last:border-0 ${rowLink("").className}`}>
                      <td className="px-3 py-2.5"><SeverityChip level={finding.severity} /></td>
                      <td className="px-3 py-2.5"><span className="redsim-chip">{finding.status}</span></td>
                      <td className="px-3 py-2.5">
                        <a
                          href={`/findings/${finding.id}`}
                          className="redsim-link"
                        >
                          {finding.schema_blob.title ?? finding.id}
                        </a>
                      </td>
                      <td className="px-3 py-2.5">
                        <RoleGated minRole="approver" callerRole={llmRole}>
                          <button
                            onClick={async () => {
                              const reason = window.prompt(
                                "Reason for dismissal",
                              );
                              if (!reason) return;
                              try {
                                setActionError("");
                                await dismissFinding(
                                  finding.id,
                                  reason,
                                  finding.status,
                                );
                                await Promise.all([mutate(), mutateFindings()]);
                              } catch (cause) {
                                setActionError(String(cause));
                              }
                            }}
                            className="redsim-ghost redsim-btn-sm"
                          >
                            Dismiss
                          </button>
                        </RoleGated>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-sm text-ink-3">
                {llmActive
                  ? "Findings are raised when the probe run completes."
                  : "No findings were raised for this run."}
              </p>
            ),
          )}
          {actionError && (
            <p className="text-sm text-destructive">{actionError}</p>
          )}
          {panel(
            5,
            "Audit chain",
            <AuditChainBadge
              state={data?.audit?.state ?? "pending"}
              events={data?.audit?.events}
              chainId={`run:${params.id}`}
            />,
          )}
        </div>
      </div>
    );
  }

  if (error && campaignMissing && !runDetail && !runError)
    // The campaign record is missing; wait for GET /v1/runs/{id} to say
    // whether this is a probe run before reporting the campaign as absent.
    return (
      <div className="space-y-3">
        <div className="h-8 w-64 animate-pulse rounded-[4px] bg-surface-2" />
        <div className="h-40 animate-pulse rounded-[4px] bg-surface-2" />
      </div>
    );
  if (error)
    return (
      <div className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
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
        <div className="h-8 w-64 animate-pulse rounded-[4px] bg-surface-2" />
        <div className="h-40 animate-pulse rounded-[4px] bg-surface-2" />
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
  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4 pb-2">
        <div className="min-w-0">
          <div className="redsim-kicker">Campaign review</div>
          <div className="mt-1 flex flex-wrap items-center gap-4">
            <h1 className="m-0 font-mono text-[1.375rem] font-medium tracking-normal">{params.id}</h1>
            <RunStatusBadge status={campaign.status} />
            <AuditChainBadge
              state={campaign.audit?.state ?? "pending"}
              events={campaign.audit?.events}
              chainId={`run:${params.id}`}
            />
          </div>
        </div>
        <div className="flex items-center gap-3 text-xs font-medium">
          {(["html", "json", "md"] as const).map((ext) => (
            <RoleGated key={ext} minRole="scanner" callerRole={role}>
              <a
                className="redsim-link"
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
                className="redsim-ghost redsim-btn-sm border-destructive/40 text-destructive"
              >
                Cancel run
              </button>
            </RoleGated>
          )}
        </div>
      </header>
      <StageTimeline stages={stages} />
      {cancelError && (
        <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {cancelError}
        </p>
      )}
      <div>
        {panel(
          1,
          "Completeness",
          <div>
            <p className="redsim-prose m-0 text-base">
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
            <p className="mt-2 text-xs text-ink-3">
              {campaign.stages_done.join(" · ") ||
                "No completed stages recorded"}
              {campaign.error ? ` — ${campaign.error}` : ""}
            </p>
          </div>,
        )}
        {panel(
          2,
          "Campaign settings",
          <dl className="m-0 grid grid-cols-2 gap-x-6 gap-y-3 text-sm md:grid-cols-4 [&_dd]:m-0 [&_dd]:text-ink-1">
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
              <dd>{campaign.config.finding_asr_threshold ?? "not recorded"}</dd>
            </div>
            <div>
              <dt className="redsim-kicker">dataset</dt>
              <dd>{campaign.config.dataset_id}</dd>
            </div>
            <div>
              <dt className="redsim-kicker">dataset revision</dt>
              <dd className="break-all font-mono text-xs">
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
              <dd className="break-all font-mono text-xs">
                {campaign.settings_hash ?? "not recorded"}
              </dd>
            </div>
            <div>
              <dt className="redsim-kicker">framework versions</dt>
              <dd>
                {Object.entries(
                  campaign.target.metadata.framework_versions ?? {},
                )
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
              (campaign.missing.join(", ") || "required evidence is incomplete")
            }
          />,
        )}
        {panel(
          4,
          "Measurements & robustness",
          <div className="grid gap-8 lg:grid-cols-[1.2fr_1fr]">
            <MeasurementTable measurements={campaign.measurements} />
            <RobustnessCurve points={campaign.curve} />
          </div>,
        )}
        {panel(
          5,
          "Observation gallery",
          <div className="gap-3 md:grid-cols-2 grid">
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
                className="border-l-2 border-line-strong pl-4"
              >
                <LabelBadge variant="inferred" />{" "}
                <span className="redsim-prose mt-1 block text-base">{item.statement}</span>
                <div className="mt-1 text-xs text-ink-3">
                  basis:{" "}
                  {item.basis.map((basis) => (
                    <a
                      key={basis}
                      href={`#${basis}`}
                      className="redsim-link ml-1"
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
              <div key={item.id} className="border-b border-line pb-4 text-sm last:border-0 last:pb-0">
                <LabelBadge
                  variant={item.measured ? "measured" : "candidate"}
                  measuredDelta={
                    item.measured
                      ? (item.measured.delta_mri ?? null)
                      : undefined
                  }
                />
                <div className="mt-2 text-base font-semibold text-ink-1">{item.title}</div>
                <p className="redsim-prose mt-1 text-base">{item.rationale}</p>
                <div className="mt-1 text-xs text-ink-3">
                  triggered by{" "}
                  {item.triggered_by.map((basis) => (
                    <a
                      key={basis}
                      href={`#${basis}`}
                      className="redsim-link ml-1"
                    >
                      {basis}
                    </a>
                  ))}{" "}
                  · {item.narrative_source} narrative · {item.validation}
                </div>
                {item.measured && (
                  <p className="mt-1 text-xs tabular-nums text-ink-1">
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
                    className="redsim-input mt-3 inline-block w-auto py-1.5"
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
                    disabled={!item.finding_id || !defenseSelections[item.id]}
                    className="redsim-ghost redsim-btn-sm ml-2"
                  >
                    Verify
                  </button>
                  {!item.finding_id && (
                    <p className="mt-2 text-xs text-ink-3">
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
          <ul className="redsim-prose m-0 list-disc space-y-1 pl-5 text-base">
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
            <dl className="m-0 grid grid-cols-2 gap-x-6 gap-y-3 text-sm md:grid-cols-4 [&_dd]:m-0 [&_dd]:break-all [&_dd]:text-ink-1">
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
                className="redsim-ghost redsim-btn-sm mt-4"
              >
                Rerun same config
              </button>
            </RoleGated>
          </div>,
        )}
        {panel(
          10,
          "Reviewer notes",
          <div className="redsim-panel p-4">
            <textarea
              aria-label="Reviewer notes"
              value={notes ?? campaign.reviewer_notes ?? ""}
              onChange={(event) => setNotes(event.target.value)}
              readOnly={!canAnnotate}
              aria-readonly={!canAnnotate}
              className="redsim-input min-h-24 font-serif text-base leading-relaxed"
            />
            <RoleGated minRole="remediator" callerRole={role}>
              <button
                onClick={saveNotes}
                className="redsim-cta redsim-btn-sm mt-3"
              >
                Save notes
              </button>
            </RoleGated>
            {noteError && (
              <p className="mt-2 text-sm text-destructive">{noteError}</p>
            )}
            {!canAnnotate && (
              <p className="mt-2 text-xs text-ink-3">
                Reviewer notes are read-only for this role.
              </p>
            )}
          </div>,
        )}
        {panel(
          11,
          "Findings",
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-line-strong">
                <th className="px-3 py-2.5 font-medium">Severity</th>
                <th className="px-3 py-2.5 font-medium">Attack</th>
                <th className="px-3 py-2.5 font-medium">First ε</th>
                <th className="px-3 py-2.5 font-medium">Finding</th>
                <th className="px-3 py-2.5 font-medium">Review</th>
              </tr>
            </thead>
            <tbody>
              {campaign.findings?.map((finding) => (
                <tr key={finding.id} {...rowLink(`/findings/${finding.id}`)} className={`border-b border-line last:border-0 ${rowLink("").className}`}>
                  <td className="px-3 py-2.5"><SeverityChip level={finding.severity} /></td>
                  <td className="px-3 py-2.5 font-mono text-xs">{finding.schema_blob.ml?.attack_id ?? "—"}</td>
                  <td className="px-3 py-2.5 tabular-nums">{finding.schema_blob.ml?.first_success_eps ?? "—"}</td>
                  <td className="px-3 py-2.5">
                    <a
                      href={`/findings/${finding.id}`}
                      className="redsim-link"
                    >
                      {finding.schema_blob.title ?? finding.id}
                    </a>
                  </td>
                  <td className="px-3 py-2.5">
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
                        className="redsim-ghost redsim-btn-sm"
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
          <div className="redsim-panel p-4">
            <label className="inline-flex items-center gap-2 text-sm">
              Compare with run
              <input
                value={compareId}
                onChange={(event) => setCompareId(event.target.value)}
                className="redsim-input inline-block w-64 font-mono text-xs"
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
              className="redsim-ghost redsim-btn-sm ml-2"
            >
              Compare
            </button>
            {compareResult?.mode === "verify_delta" && (
              <div className="mt-4 border-t border-line pt-4 text-sm tabular-nums">
                <strong className="text-ink-1">Measured verify comparison</strong>
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
                  <table className="mt-3 w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-line-strong">
                        <th className="px-2 py-2 font-medium">Family</th>
                        <th className="px-2 py-2 text-right font-medium">Before</th>
                        <th className="px-2 py-2 text-right font-medium">After</th>
                      </tr>
                    </thead>
                    <tbody>
                      {compareResult.delta_families.map((family) => (
                        <tr
                          key={family.family}
                          className="border-b border-line last:border-0"
                        >
                          <td className="px-2 py-2 text-ink-1">{family.family}</td>
                          <td className="px-2 py-2 text-right tabular-nums">
                            {family.before} (n={family.n_before})
                          </td>
                          <td className="px-2 py-2 text-right tabular-nums">
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
              <div className="mt-4 grid gap-6 border-t border-line pt-4 md:grid-cols-2">
                {(compareResult.scorecards ?? []).map((scorecard, index) => (
                  <div key={index} className="space-y-4 text-sm">
                    <strong className="block text-ink-1">
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
                      <p className="mt-2 text-xs text-ink-3">
                        Measurement table unavailable.
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
            {compareResult && (
              <div className="mt-3 text-xs text-ink-2">
                <p>
                  Changed variables:{" "}
                  {compareResult.changed_variables.join(", ") || "none"}
                </p>
                <p>
                  Unchanged variables:{" "}
                  {compareResult.unchanged_variables.join(", ") || "none"}
                </p>
                {compareResult.caveats.map((caveat) => (
                  <p key={caveat} className="text-ink-3">
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
