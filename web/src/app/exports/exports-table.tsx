"use client";

// The client leaf of /exports.
//
// One row per campaign run with the state of its report formats and
// of its adversarial dataset export, read in one query from the `exports`
// router. The actions on a row call the API's own gated routes through the
// router (`report.render` for a re-render, `dataset.export` for a dataset) and
// the API's refusal is shown beside the row with its code, never rewritten.
// Role gating here is presentation only; the API is the authorization
// boundary (spec 7.9).

import Link from "next/link";
import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";

import {
  RoleGated,
  RunStatusBadge,
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@redsim/design-system";
import {
  REPORT_EXTS,
  datasetManifestUrl,
  reportUrl,
  upstreamError,
  type ExportDatasetBlocker,
  type ExportRow,
  type ReportExt,
} from "@/lib/api";
import { formatBytes, formatDateTime } from "@/lib/format-datetime";
import { rowLink } from "@/lib/row-link";
import { useTRPC } from "@/lib/trpc/client";
import { useRoles } from "@/hooks/useRoles";

/** The poll for a list whose rows change while jobs run, in milliseconds. */
export const EXPORTS_POLL_MS = 15_000;

export type ExportsTableProps = {
  project?: string;
  limit?: number;
};

/** What each admission blocker means to a reader (spec 27.1, `admit_export`). */
const BLOCKER_TEXT: Record<ExportDatasetBlocker, string> = {
  not_terminal: "run not finished",
  run_failed: "run did not succeed",
  fixture_target: "fixture target, never exported",
  no_slices: "no adversarial slices retained",
};

function shortDigest(sha256: string | null): string {
  if (!sha256) return "—";
  return sha256.length > 12 ? `${sha256.slice(0, 12)}…` : sha256;
}

/** The API refusal beside a row, as `{code, message}` text. */
function refusalText(error: unknown): string {
  const upstream = upstreamError(error);
  if (upstream) return `${upstream.code}: ${upstream.message}`;
  return error instanceof Error ? error.message : "request failed";
}

function ReportCell({
  row,
  role,
  onRender,
  pending,
}: {
  row: ExportRow;
  role: string | undefined;
  onRender: () => void;
  pending: boolean;
}) {
  const { reports } = row;
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap gap-2 text-xs">
        {REPORT_EXTS.map((ext: ReportExt) => {
          const ref = reports.formats[ext];
          return ref ? (
            <a
              key={ext}
              className="font-mono text-primary underline"
              href={reportUrl(row.run_id, ext)}
              target="_blank"
              rel="noreferrer"
              title={`sha256 ${ref.sha256} · ${formatBytes(ref.size_bytes)}`}
            >
              {ext.toUpperCase()}
            </a>
          ) : (
            <span
              key={ext}
              className="font-mono text-muted-foreground line-through"
              title="not rendered"
            >
              {ext.toUpperCase()}
            </span>
          );
        })}
      </div>
      <div className="text-xs text-muted-foreground">
        {reports.snapshot_count > 0 && reports.latest_snapshot
          ? `snapshot v${reports.latest_snapshot.version}`
          : reports.available.length > 0
            ? "no snapshot"
            : "not rendered"}
        {reports.render_in_flight ? " · render in flight" : null}
      </div>
      {row.terminal && !reports.render_in_flight ? (
        <RoleGated minRole="scanner" callerRole={role}>
          <button
            type="button"
            className="redsim-ghost px-2 py-0.5 text-xs"
            disabled={pending}
            onClick={onRender}
          >
            {pending ? "Rendering…" : "Render again"}
          </button>
        </RoleGated>
      ) : null}
    </div>
  );
}

function DatasetCell({
  row,
  role,
  onExport,
  pending,
}: {
  row: ExportRow;
  role: string | undefined;
  onExport: () => void;
  pending: boolean;
}) {
  const { dataset } = row;
  const canStart =
    (dataset.status === "not_exported" || dataset.status === "failed") &&
    dataset.blockers.length === 0;
  return (
    <div className="space-y-1 text-xs">
      {dataset.status === "exported" ? (
        <>
          <a
            className="text-primary underline"
            href={datasetManifestUrl(row.run_id)}
            target="_blank"
            rel="noreferrer"
          >
            Croissant manifest
          </a>
          <div className="text-muted-foreground">
            {dataset.files} Parquet {dataset.files === 1 ? "file" : "files"} ·{" "}
            {formatBytes(dataset.bytes)} · manifest{" "}
            <span className="font-mono" title={dataset.manifest_sha256 ?? undefined}>
              {shortDigest(dataset.manifest_sha256)}
            </span>
            {dataset.card ? " · card" : null}
          </div>
        </>
      ) : dataset.status === "queued" || dataset.status === "running" ? (
        <div className="text-muted-foreground">
          export {dataset.status}
          {dataset.follow_up_run_id ? (
            <>
              {" · "}
              <Link className="text-primary underline" href={`/runs/${dataset.follow_up_run_id}`}>
                follow-up run
              </Link>
            </>
          ) : null}
        </div>
      ) : dataset.status === "failed" ? (
        <div className="text-warning">
          export failed{dataset.error ? `: ${dataset.error}` : ""}
        </div>
      ) : (
        <div className="text-muted-foreground">not exported</div>
      )}
      {dataset.blockers.length > 0 ? (
        <div className="text-muted-foreground">
          {dataset.blockers.map((blocker) => BLOCKER_TEXT[blocker]).join(" · ")}
        </div>
      ) : null}
      {canStart ? (
        <RoleGated minRole="remediator" callerRole={role}>
          <button
            type="button"
            className="redsim-ghost px-2 py-0.5 text-xs"
            disabled={pending}
            onClick={onExport}
          >
            {pending
              ? "Starting…"
              : dataset.status === "failed"
                ? "Retry dataset export"
                : "Export dataset"}
          </button>
        </RoleGated>
      ) : null}
    </div>
  );
}

export function ExportsTable({ project, limit }: ExportsTableProps) {
  const trpc = useTRPC();
  const query = useQuery({
    ...trpc.exports.list.queryOptions({ project, limit }),
    refetchInterval: EXPORTS_POLL_MS,
  });
  const { roles } = useRoles();

  // Per-row action state, keyed by run and action so two rows (or the two
  // actions of one row) in flight at once never overwrite each other. The
  // last refusal per run stays until the next attempt on that run.
  const [pending, setPending] = useState<Set<string>>(() => new Set());
  const [refusals, setRefusals] = useState<Record<string, string>>({});

  const begin = (key: string, runId: string) => {
    setPending((prev) => new Set(prev).add(key));
    setRefusals((prev) => {
      if (!(runId in prev)) return prev;
      const next = { ...prev };
      delete next[runId];
      return next;
    });
  };
  const settle = (key: string, runId: string) => (error?: unknown) => {
    setPending((prev) => {
      const next = new Set(prev);
      next.delete(key);
      return next;
    });
    if (error) setRefusals((prev) => ({ ...prev, [runId]: refusalText(error) }));
    void query.refetch();
  };

  const renderReport = useMutation(trpc.exports.renderReport.mutationOptions());
  const exportDataset = useMutation(trpc.exports.exportDataset.mutationOptions());

  const startRender = (runId: string) => {
    const key = `${runId}:render`;
    begin(key, runId);
    renderReport.mutate({ runId }, { onSuccess: () => settle(key, runId)(), onError: settle(key, runId) });
  };
  const startExport = (runId: string) => {
    const key = `${runId}:export`;
    begin(key, runId);
    exportDataset.mutate({ runId }, { onSuccess: () => settle(key, runId)(), onError: settle(key, runId) });
  };

  const upstream = upstreamError(query.error);

  if (query.error && query.data === undefined) {
    return (
      <div
        role="alert"
        className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
      >
        <p>
          Exports are unavailable: <code>{upstream?.code ?? "unknown_error"}</code>
        </p>
        {upstream?.message ? <p className="mt-1">{upstream.message}</p> : null}
        <button type="button" className="mt-2 underline" onClick={() => void query.refetch()}>
          Retry
        </button>
      </div>
    );
  }

  const rows = query.data?.exports ?? [];

  const stale = query.error ? (
    <div
      role="status"
      className="rounded-md border border-border bg-muted/50 p-3 text-sm text-muted-foreground"
    >
      <p>
        These rows may be out of date: <code>{upstream?.code ?? "unknown_error"}</code>
      </p>
      <button type="button" className="mt-2 underline" onClick={() => void query.refetch()}>
        Retry
      </button>
    </div>
  ) : null;

  if (rows.length === 0) {
    return (
      <div className="space-y-3">
        {stale}
        <p className="text-muted-foreground">
          Nothing to export yet. A finished campaign appears here with its
          report formats and its dataset export. Start one from{" "}
          <Link className="text-primary underline" href="/models">
            /models
          </Link>
          .
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {stale}
      <div className="overflow-x-auto rounded-md border border-border bg-card">
        <Table>
          <TableCaption className="sr-only">Exports by run</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead scope="col">Run</TableHead>
              <TableHead scope="col">Model</TableHead>
              <TableHead scope="col">Status</TableHead>
              <TableHead scope="col">Reports</TableHead>
              <TableHead scope="col">Dataset</TableHead>
              <TableHead scope="col">Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => {
              const role = roles[row.project_id];
              const refusal = refusals[row.run_id];
              return (
                <TableRow key={row.run_id} {...rowLink(`/runs/${row.run_id}`)}>
                  <TableCell className="font-mono text-xs">
                    <Link className="text-primary underline" href={`/runs/${row.run_id}`}>
                      {row.run_id}
                    </Link>
                    {refusal ? (
                      <div role="alert" className="mt-1 max-w-xs font-sans text-xs text-warning">
                        {refusal}
                      </div>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <div>{row.model.name ?? "not recorded"}</div>
                    <div className="text-xs text-muted-foreground">
                      {row.model.modality ?? "modality not recorded"}
                      {row.model.fixture ? " · fixture" : null}
                    </div>
                  </TableCell>
                  <TableCell>
                    <RunStatusBadge status={row.status} />
                  </TableCell>
                  <TableCell>
                    <ReportCell
                      row={row}
                      role={role}
                      pending={pending.has(`${row.run_id}:render`)}
                      onRender={() => startRender(row.run_id)}
                    />
                  </TableCell>
                  <TableCell>
                    <DatasetCell
                      row={row}
                      role={role}
                      pending={pending.has(`${row.run_id}:export`)}
                      onExport={() => startExport(row.run_id)}
                    />
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatDateTime(row.created_at)}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
