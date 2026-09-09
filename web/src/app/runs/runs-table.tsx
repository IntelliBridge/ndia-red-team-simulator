"use client";

// The client leaf of /runs.
//
// It never early-returns on isPending: the page awaits this key, so it
// hydrates with data or with its typed error and the loading branch R9
// forbids does not exist here. Skeletons live in loading.tsx.

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";

import {
  RunStatusBadge,
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@redsim/design-system";
import { upstreamError } from "@/lib/api";
import { useTRPC } from "@/lib/trpc/client";

/** R10's poll fallback for a list page, in milliseconds. */
export const RUNS_POLL_MS = 15_000;

/**
 * A timestamp the server and the client format identically.
 *
 * The shipped page called `toLocaleString()` with no arguments, which reads
 * the host locale and time zone, so the server HTML and the first client
 * render disagreed and React replaced the cell. Pinning both to UTC and
 * en-US, with the zone visible so nobody reads it as local time, is what
 * makes the hydrated markup stable. U5 owns the shared helper; this is the
 * same pinned call, replaced when it lands.
 */
export function formatDateTime(iso: string): string {
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return "not recorded";
  return `${parsed.toLocaleString("en-US", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  })} UTC`;
}

export type RunsTableProps = {
  project?: string;
  limit?: number;
};

export function RunsTable({ project, limit }: RunsTableProps) {
  const trpc = useTRPC();
  const query = useQuery({
    ...trpc.runs.list.queryOptions({ project, limit }),
    refetchInterval: RUNS_POLL_MS,
  });

  if (query.error) {
    const upstream = upstreamError(query.error);
    return (
      <div
        role="alert"
        className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
      >
        <p>
          Runs are unavailable: <code>{upstream?.code ?? "unknown_error"}</code>
        </p>
        {upstream?.message ? <p className="mt-1">{upstream.message}</p> : null}
        <button
          type="button"
          className="mt-2 underline"
          onClick={() => void query.refetch()}
        >
          Retry
        </button>
      </div>
    );
  }

  const runs = query.data?.runs ?? [];

  if (runs.length === 0) {
    return (
      <p className="text-muted-foreground">
        No runs yet. Head to{" "}
        <Link className="text-primary underline" href="/models">
          /models
        </Link>{" "}
        to register a target and start one.
      </p>
    );
  }

  return (
    <div className="overflow-hidden rounded-md border border-border bg-card">
      <Table>
        <TableCaption className="sr-only">All runs</TableCaption>
        <TableHeader>
          <TableRow>
            <TableHead scope="col">Run</TableHead>
            <TableHead scope="col">Model</TableHead>
            <TableHead scope="col">Attacks</TableHead>
            <TableHead scope="col">Status</TableHead>
            <TableHead scope="col">Created</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {runs.map((run) => (
            <TableRow key={run.id}>
              <TableCell className="font-mono text-xs">
                <Link className="text-primary underline" href={`/runs/${run.id}`}>
                  {run.id}
                </Link>
              </TableCell>
              {/* The run row carries a scanner, not a model or an attack list.
                  Until the API grows a per-run campaign summary these read
                  "not recorded" rather than inventing a value (KTD12). */}
              <TableCell className="text-muted-foreground">
                {run.scanner ?? "not recorded"}
              </TableCell>
              <TableCell className="text-muted-foreground">not recorded</TableCell>
              <TableCell>
                <RunStatusBadge status={run.status} />
              </TableCell>
              <TableCell className="text-muted-foreground">
                {formatDateTime(run.created_at)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
