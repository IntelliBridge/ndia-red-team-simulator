"use client";

// /runs — all runs list.
//
// The dashboard shows recent runs; this is the dedicated, linkable list
// page (the nav's command palette can route here). SWR over GET /v1/runs
// with the design-system Table + RunStatusBadge so styling matches the
// dashboard. Semantic tokens only; table carries a caption + scope.

import useSWR from "swr";

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
import { api, type Run } from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";

const fetcher = (path: string) => api<{ runs: Run[]; count: number }>(path);

export default function RunsPage() {
  const authed = useRequireAuth();
  const { data, error, isLoading } = useSWR(authed ? "/v1/runs" : null, fetcher);

  if (!authed)
    return <p className="text-muted-foreground">Redirecting to sign in…</p>;

  const runs = data?.runs ?? [];

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Runs</h1>

      {isLoading && <p className="text-muted-foreground">Loading…</p>}
      {error && (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          Failed to load runs: {String(error)}
        </p>
      )}
      {!isLoading && !error && runs.length === 0 && (
        <p className="text-muted-foreground">
           No runs yet. Head to{" "}
           <a className="text-primary underline" href="/models">
             /models
          </a>{" "}
          to register a target and start one.
        </p>
      )}
      {runs.length > 0 && (
        <div className="overflow-hidden rounded-md border border-border bg-card">
          <Table>
            <TableCaption className="sr-only">All runs</TableCaption>
            <TableHeader>
              <TableRow>
                <TableHead scope="col">Run</TableHead>
                <TableHead scope="col">Project</TableHead>
                <TableHead scope="col">Scanner</TableHead>
                <TableHead scope="col">Status</TableHead>
                <TableHead scope="col">Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="font-mono text-xs">
                    <a className="text-primary underline" href={`/runs/${r.id}`}>
                      {r.id}
                    </a>
                  </TableCell>
                  <TableCell>{r.project_id}</TableCell>
                  <TableCell>{r.scanner ?? "—"}</TableCell>
                  <TableCell>
                    <RunStatusBadge status={r.status} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {new Date(r.created_at).toLocaleString()}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
