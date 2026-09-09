"use client";

// The k/n probe scorecard of an LLM probe run (spec 15.9 / D9).
//
// A probe run is never a campaign: it carries hit counts per (probe, detector)
// row and no MRI, grade or subscore. This panel therefore renders fractions
// with their denominators and never a pooled rate. The route answers 409
// score_unavailable until the worker writes the artifact; useLlmScorecard maps
// that to `ready: false`, which is a waiting state here, not an error.

import { ApiError, artifactUrl, centsToUsd, mlErrorDetail } from "@/lib/api";
import {
  guardrailLabel,
  scorecardRows,
  type LlmDetectorRow,
  type LlmScorecardResponse,
  type LlmScorecardRow,
} from "@/lib/llm";

export type LlmScorecardPanelProps = {
  response?: LlmScorecardResponse | null;
  ready: boolean;
  error?: unknown;
  /** Run status from GET /v1/runs/{id} (or the campaign payload). */
  runStatus?: string | null;
  /** stage_table.error of a failed run, when recorded. */
  runError?: string | null;
};

const ACTIVE = new Set(["queued", "running"]);

function fraction(row: LlmDetectorRow): string {
  return `${row.n_hits}/${row.n_evaluated}`;
}

function percent(row: LlmDetectorRow): string {
  if (row.hit_rate == null || row.n_evaluated === 0) return "not computed";
  return `${(row.hit_rate * 100).toFixed(1)}%`;
}

function statusLabel(status: string | null | undefined): string {
  switch (status) {
    case "queued":
      return "queued";
    case "running":
      return "running";
    case "failed":
      return "failed";
    case "cancelled":
      return "cancelled";
    case "succeeded":
      return "succeeded";
    default:
      return status ?? "unknown";
  }
}

function DetectorCells({ detector }: { detector: LlmDetectorRow }) {
  if (detector.status === "not_run") {
    return (
      <>
        <td className="font-mono">—</td>
        <td className="text-muted-foreground">
          not run{detector.reason ? ` — ${detector.reason}` : ""}
        </td>
      </>
    );
  }
  return (
    <>
      <td className="font-mono">
        <span className="font-semibold">{fraction(detector)}</span>
        <span className="ml-1 text-muted-foreground">
          ({percent(detector)})
        </span>
        {detector.ci_lower != null && detector.ci_upper != null && (
          <span className="ml-1 text-muted-foreground">
            CI {((detector.ci_lower ?? 0) * 100).toFixed(0)}–
            {((detector.ci_upper ?? 0) * 100).toFixed(0)}%
          </span>
        )}
      </td>
      <td className="text-muted-foreground">
        {detector.n_passed} passed
        {detector.n_none ? ` · ${detector.n_none} unscored` : ""}
      </td>
    </>
  );
}

function ProbeRows({ probe }: { probe: LlmScorecardRow }) {
  // Detector order is the catalog's: the primary detector comes first and
  // carries the probe cells; extended detectors follow as muted sub-rows.
  const [primary, ...extended] = probe.detectors;
  const probeStatus =
    probe.status === "run"
      ? "run"
      : `${probe.status}${probe.reason ? ` — ${probe.reason}` : ""}`;
  const attempts = `${probe.n_prompts_sent}${
    probe.n_prompts_after_cap != null &&
    probe.n_prompts_after_cap !== probe.n_prompts_sent
      ? ` of ${probe.n_prompts_after_cap}`
      : ""
  }${probe.n_outputs_blocked ? ` · ${probe.n_outputs_blocked} blocked` : ""}`;
  return (
    <>
      <tr className="border-border border-t align-top">
        <td className="font-mono">
          <div>{probe.short_id || probe.probe_id}</div>
          {probe.short_id && probe.short_id !== probe.probe_id && (
            <div className="text-muted-foreground">{probe.probe_id}</div>
          )}
        </td>
        <td>{probe.goal || "—"}</td>
        <td className="font-mono">{attempts}</td>
        {primary ? (
          <DetectorCells detector={primary} />
        ) : (
          <>
            <td className="font-mono">—</td>
            <td className="text-muted-foreground">no detector row</td>
          </>
        )}
        <td className={probe.status === "run" ? "" : "text-muted-foreground"}>
          {probeStatus}
        </td>
        <td className="font-mono">{primary?.detector ?? "—"}</td>
      </tr>
      {extended.map((detector) => (
        <tr
          key={detector.row_id}
          className="border-border/40 text-muted-foreground border-t align-top"
        >
          <td />
          <td className="italic">extended detector</td>
          <td />
          <DetectorCells detector={detector} />
          <td />
          <td className="font-mono">{detector.detector}</td>
        </tr>
      ))}
    </>
  );
}

export function LlmScorecardPanel({
  response,
  ready,
  error,
  runStatus,
  runError,
}: LlmScorecardPanelProps) {
  if (error) {
    const detail = mlErrorDetail(error);
    const notProbe =
      error instanceof ApiError && detail.code === "llm_target_required";
    return (
      <div className="border-destructive/40 bg-destructive/10 p-4 text-sm border">
        {notProbe
          ? "This run is not an LLM probe run; the k/n scorecard route does not apply to it."
          : error instanceof ApiError
            ? `Scorecard unavailable (${error.status})${detail.message ? `: ${detail.message}` : ""}.`
            : "Scorecard unavailable. Retry."}
      </div>
    );
  }

  if (!ready || !response) {
    const active = !runStatus || ACTIVE.has(runStatus);
    return (
      <div className="space-y-2 text-sm" data-testid="llm-scorecard-pending">
        {active ? (
          <>
            <p>
              Probe run in progress — the scorecard appears when the worker
              finishes.
            </p>
            <p className="text-xs text-muted-foreground">
              run status: {statusLabel(runStatus)} · this page polls the
              scorecard route while the run is active
            </p>
            <div className="h-24 animate-pulse bg-muted" />
          </>
        ) : (
          <>
            <p>
              Probe run {statusLabel(runStatus)} without a scorecard. Recorded
              partial artifacts are preserved.
            </p>
            {runError && (
              <p className="text-xs text-muted-foreground">
                reason: {runError}
              </p>
            )}
          </>
        )}
      </div>
    );
  }

  const { scorecard, artifact } = response;
  const rows = scorecardRows(scorecard);
  const nRun = rows.filter((row) => row.status === "run").length;
  const nNotRun = rows.filter((row) => row.status === "not_run").length;
  const nFailed = rows.filter((row) => row.status === "failed").length;
  const nPromptsSent = rows.reduce((sum, row) => sum + row.n_prompts_sent, 0);
  const nRowsWithHits = rows.reduce(
    (sum, row) =>
      sum +
      row.detectors.filter((d) => d.status === "run" && d.n_hits > 0).length,
    0,
  );
  const usage = scorecard.usage;
  const modelsSeen = Object.entries(
    scorecard.models_seen ?? usage?.models_seen ?? {},
  );
  const requestedIds =
    scorecard.probe_ids ?? scorecard.probe_ids_requested ?? [];
  const excludedProbes =
    scorecard.excluded_probes ?? scorecard.not_admitted ?? [];
  const limitations = scorecard.limitations ?? [];
  const probeSet =
    scorecard.probe_set ?? `${requestedIds.length} probes selected by id`;

  return (
    <div className="space-y-4 text-sm" data-testid="llm-scorecard">
      <p className="text-xs text-muted-foreground">
        k hits / n evaluated outputs per probe and detector. No MRI or grade is
        derived from LLM probe results (D9).
      </p>
      <dl className="gap-4 md:grid-cols-4 grid grid-cols-2">
        <div>
          <dt className="redsim-kicker">target model</dt>
          <dd className="font-mono break-all">{scorecard.model_id}</dd>
        </div>
        <div>
          <dt className="redsim-kicker">persona</dt>
          <dd>{scorecard.persona ?? "not recorded"}</dd>
        </div>
        <div>
          <dt className="redsim-kicker">guardrail mode</dt>
          <dd>{guardrailLabel(scorecard.guardrail_mode)}</dd>
        </div>
        <div>
          <dt className="redsim-kicker">gateway</dt>
          <dd className="break-all">
            {scorecard.gateway_host ?? "not recorded"}
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker">probe set</dt>
          <dd>{probeSet}</dd>
        </div>
        <div>
          <dt className="redsim-kicker">detector mode</dt>
          <dd>
            {scorecard.detector_mode}
            {scorecard.extended_detectors ? " · extended" : ""}
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker">prompt cap / seed</dt>
          <dd>
            {scorecard.max_prompts_per_probe} per probe · seed {scorecard.seed}
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker">garak</dt>
          <dd>
            {scorecard.garak_version ?? "not recorded"}
            {scorecard.catalog_garak_version &&
            scorecard.catalog_garak_version !== scorecard.garak_version
              ? ` (catalog ${scorecard.catalog_garak_version})`
              : ""}
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker">probe status</dt>
          <dd>
            {scorecard.status} · {scorecard.completeness}
            {scorecard.error ? ` — ${scorecard.error}` : ""}
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker">probes</dt>
          <dd>
            {nRun} run · {nNotRun} not run · {nFailed} failed of{" "}
            {requestedIds.length} requested
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker">prompts sent</dt>
          <dd>
            {nPromptsSent}
            {usage?.gateway_blocked
              ? ` · ${usage.gateway_blocked} blocked by gateway`
              : ""}
          </dd>
        </div>
        <div>
          <dt className="redsim-kicker">rows with hits</dt>
          <dd>{nRowsWithHits}</dd>
        </div>
      </dl>

      <div className="overflow-x-auto">
        <table className="text-xs w-full text-left">
          <thead>
            <tr>
              <th>Probe</th>
              <th>Goal</th>
              <th>Attempts</th>
              <th>Hits k / n</th>
              <th>Passed</th>
              <th>Status</th>
              <th>Detector</th>
            </tr>
          </thead>
          <tbody>
            {rows.length ? (
              rows.map((probe) => (
                <ProbeRows key={probe.probe_id} probe={probe} />
              ))
            ) : (
              <tr className="border-border border-t">
                <td colSpan={7} className="py-2 text-muted-foreground">
                  The scorecard carries no probe rows.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {excludedProbes.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Not offered in this run: {excludedProbes.join(", ")}
        </p>
      )}

      {usage && (
        <div>
          <div className="redsim-kicker">usage</div>
          <p className="text-xs">
            {usage.n_requests ?? usage.requests ?? 0} requests ·{" "}
            {usage.n_responses_ok ?? usage.responses_ok ?? 0} ok ·{" "}
            {usage.total_tokens ??
              (usage.prompt_tokens ?? 0) + (usage.completion_tokens ?? 0)}{" "}
            tokens ({usage.prompt_tokens ?? 0} prompt /{" "}
            {usage.completion_tokens ?? 0} completion)
            {typeof usage.wall_time_s === "number"
              ? ` · ${usage.wall_time_s.toFixed(1)}s wall`
              : ""}
            {usage.retries ? ` · ${usage.retries} retries` : ""}
            {usage.cost_cents != null
              ? ` · ${centsToUsd(usage.cost_cents)}`
              : usage.unpriced_model
                ? " · unpriced model"
                : ""}
            {usage.tls_mode ? ` · tls ${usage.tls_mode}` : ""}
          </p>
          {modelsSeen.length > 0 && (
            <p className="text-xs text-muted-foreground">
              models seen:{" "}
              {modelsSeen.map(([id, n]) => `${id} (${n})`).join(", ")}
            </p>
          )}
          {(Object.keys(usage.http_errors ?? {}).length > 0 ||
            Object.keys(usage.transport_errors ?? {}).length > 0) && (
            <p className="text-xs text-muted-foreground">
              errors:{" "}
              {[
                ...Object.entries(usage.http_errors ?? {}).map(
                  ([code, n]) => `http ${code} ×${n}`,
                ),
                ...Object.entries(usage.transport_errors ?? {}).map(
                  ([kind, n]) => `${kind} ×${n}`,
                ),
              ].join(", ")}
            </p>
          )}
        </div>
      )}

      <div>
        <div className="redsim-kicker">limitations</div>
        <ul className="space-y-1 pl-5 text-xs list-disc">
          {(limitations.length
            ? limitations
            : ["Limitations were not recorded; evidence is incomplete."]
          ).map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </div>

      <p className="text-xs text-muted-foreground">
        scorecard artifact{" "}
        <a
          className="text-primary underline"
          href={artifactUrl(artifact.artifact_id)}
          target="_blank"
          rel="noreferrer"
        >
          {artifact.artifact_id}
        </a>{" "}
        · sha256 <span className="font-mono break-all">{artifact.sha256}</span>
        {" · "}
        {scorecard.schema_version}
      </p>
    </div>
  );
}
