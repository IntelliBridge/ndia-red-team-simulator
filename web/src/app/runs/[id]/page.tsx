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
  type ArtifactRow,
  type Campaign,
  type Comparison,
  type Finding,
  type RunDetail,
} from "@/lib/api";
import { useCampaign } from "@/hooks/useCampaign";
import { useLlmScorecard } from "@/hooks/useLlm";
import { useRequireAuth } from "@/hooks/useRequireAuth";
import { rowLink } from "@/lib/row-link";
import { useRoles } from "@/hooks/useRoles";
import { useRunEvents } from "@/hooks/useRunEvents";
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
    // campaign-only panels (MRI, eps curve, compare) do not apply.
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
      <div className="space-y-4">
        <header className="gap-4 flex flex-wrap items-end justify-between">
          <div>
            <div className="redsim-kicker">LLM probe review</div>
            <h1 className="font-mono text-2xl">{params.id}</h1>
            <div className="mt-2">
              <RunStatusBadge status={runStatus ?? "queued"} />
            </div>
          </div>
          <div className="gap-3 text-sm flex items-center">
            {hasReport &&
              (["html", "json", "md"] as const).map((ext) => (
                <RoleGated key={ext} minRole="scanner" callerRole={llmRole}>
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
            {isCancellable(runStatus) && (
              <RoleGated minRole="remediator" callerRole={llmRole}>
                <button
                  onClick={cancel}
                  className="border-destructive/30 px-3 py-1 text-destructive border"
                >
                  Cancel run
                </button>
              </RoleGated>
            )}
          </div>
        </header>
        <StageTimeline stages={stages} />
        {cancelError && (
          <p className="border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive border">
            {cancelError}
          </p>
        )}
        <div className="space-y-4">
          {panel(
            1,
            "Run status",
            <div>
              <p>
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
              <p className="mt-2 text-xs text-muted-foreground">
                {stagesDone.join(" · ") || "No completed stages recorded"}
                {stageError ? ` — ${stageError}` : ""}
              </p>
              {probeIds.length > 0 && (
                <p className="mt-2 text-xs text-muted-foreground">
                  {probeIds.length} probes requested: {probeIds.join(", ")}
                </p>
              )}
              {runDetail?.completed_at && (
                <p className="mt-1 text-xs text-muted-foreground">
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
              <table className="text-xs w-full text-left">
                <thead>
                  <tr>
                    <th>Kind</th>
                    <th>Size</th>
                    <th>sha256</th>
                    <th>Artifact</th>
                  </tr>
                </thead>
                <tbody>
                  {artifacts.map((row) => (
                    <tr key={row.id} className="border-border border-t">
                      <td className="font-mono">{row.kind ?? "—"}</td>
                      <td>
                        {typeof row.size_bytes === "number"
                          ? `${row.size_bytes} B`
                          : "—"}
                      </td>
                      <td className="font-mono text-muted-foreground break-all">
                        {row.sha256 ? row.sha256.slice(0, 16) : "—"}
                      </td>
                      <td>
                        <a
                          href={artifactUrl(row.id)}
                          target="_blank"
                          rel="noreferrer"
                          className="text-primary underline"
                        >
                          {row.id}
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-sm text-muted-foreground">
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
              <table className="text-xs w-full text-left">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Finding</th>
                    <th>Review</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.id} {...rowLink(`/findings/${finding.id}`)} className={`border-border border-t ${rowLink("").className}`}>
                      <td><SeverityChip level={finding.severity} /></td>
                      <td>{finding.status}</td>
                      <td>
                        <a
                          href={`/findings/${finding.id}`}
                          className="text-primary underline"
                        >
                          {finding.schema_blob.title ?? finding.id}
                        </a>
                      </td>
                      <td>
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
                            className="border-border px-2 py-1 border"
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
              <p className="text-sm text-muted-foreground">
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
        <div className="h-8 w-64 animate-pulse bg-muted" />
        <div className="h-40 animate-pulse bg-muted" />
      </div>
    );
  if (error)
    return (
      <div className="border-destructive/40 bg-destructive/10 p-4 text-sm border">
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
    <div className="space-y-4">
      <header className="gap-4 flex flex-wrap items-end justify-between">
        <div>
          <div className="redsim-kicker">campaign review</div>
          <h1 className="font-mono text-2xl">{params.id}</h1>
          <div className="mt-2">
            <RunStatusBadge status={campaign.status} />
          </div>
        </div>
        <div className="gap-3 text-sm flex items-center">
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
                className="border-destructive/30 px-3 py-1 text-destructive border"
              >
                Cancel run
              </button>
            </RoleGated>
          )}
        </div>
      </header>
      <StageTimeline stages={stages} />
      {cancelError && (
        <p className="border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive border">
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
          <dl className="gap-4 text-sm md:grid-cols-3 grid grid-cols-2">
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
          <div className="gap-5 lg:grid-cols-[1.2fr_1fr] grid">
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
                className="border-accent pl-3 text-sm border-l-2"
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
              <div key={item.id} className="border-border p-3 text-sm border">
                <LabelBadge variant="candidate" />
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
                  · {item.status} · {item.narrative_source} narrative
                </div>
              </div>
            ))}
          </div>,
        )}
        {panel(
          8,
          "Limitations",
          <ul className="space-y-1 pl-5 text-sm list-disc">
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
            <dl className="gap-3 text-sm grid grid-cols-2">
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
                    target_snapshot: _targetSnapshot,
                    attacks: _attacks,
                    ...request
                  } = campaign.config;
                  // The route is keyed by the Target row id frozen into the config,
                  // not the registry id the target block carries.
                  const result = await startCampaign(
                    _targetId || campaign.target.id,
                    request,
                  );
                  window.location.assign(`/runs/${result.run_id}`);
                }}
                className="mt-3 border-border px-3 py-2 text-sm border"
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
              className="min-h-24 rounded-sm border-input bg-background p-3 text-sm w-full border"
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
          <table className="text-xs w-full text-left">
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
                <tr key={finding.id} {...rowLink(`/findings/${finding.id}`)} className={`border-border border-t ${rowLink("").className}`}>
                  <td><SeverityChip level={finding.severity} /></td>
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
                        className="border-border px-2 py-1 border"
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
                className="ml-2 border-input bg-background p-2 border"
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
              className="ml-2 border-border px-3 py-2 text-sm border"
            >
              Compare
            </button>
            {compareResult?.mode === "side_by_side" && (
              <div className="mt-3 gap-3 md:grid-cols-2 grid">
                {(compareResult.scorecards ?? []).map((scorecard, index) => (
                  <div key={index} className="border-border p-3 text-sm border">
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
