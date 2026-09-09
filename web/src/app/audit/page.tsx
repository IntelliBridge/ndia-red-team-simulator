"use client";

import useSWR from "swr";

import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@redsim/design-system";
import { api } from "@/lib/api";
import { useRequireAuth } from "@/hooks/useRequireAuth";

interface ChainEvent {
  seq: number;
  this_hash: string;
  prev_hash: string | null;
}

interface ChainStatus {
  chain_id: string;
  verified: boolean;
  event_count: number;
  head_hash: string | null;
  /**
   * Optional per-event detail for the chain visualization. When the verify
   * endpoint returns events we render them as linked blocks; otherwise we
   * fall back to a compact head-only summary node.
   */
  events?: ChainEvent[];
  /** First seq at which the chain breaks (1-based), if any. */
  broken_at?: number | null;
}

interface VerifyResponse {
  chains: ChainStatus[];
}

const fetcher = (path: string) => api<VerifyResponse>(path);

function truncHash(hash: string | null | undefined): string {
  if (!hash) return "—";
  return hash.length > 16 ? hash.slice(0, 16) + "…" : hash;
}

/** A single hash node: shows the truncated hash, full hash on hover. */
function HashNode({
  label,
  hash,
  broken,
}: {
  label: string;
  hash: string | null;
  broken?: boolean;
}) {
  const tone = broken
    ? "border-destructive text-destructive"
    : "border-line-strong text-ink-2";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={`inline-flex flex-col rounded-[3px] border bg-ground px-2 py-1 font-mono text-[11px] ${tone}`}
          data-testid={`hash-${label}`}
        >
          <span className="text-[10px] text-ink-3">
            {label}
          </span>
          <span>{truncHash(hash)}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent className="font-mono text-xs">
        {hash ?? "(none)"}
      </TooltipContent>
    </Tooltip>
  );
}

/** The arrow/link between two consecutive blocks. */
function ChainLink({ broken }: { broken?: boolean }) {
  return (
    <span
      aria-hidden="true"
      className={broken ? "px-1 text-destructive" : "px-1 text-ink-4"}
    >
      {broken ? "⤬" : "→"}
    </span>
  );
}

function ChainCard({ chain }: { chain: ChainStatus }) {
  const events = chain.events ?? [];
  const statusTone = chain.verified ? "text-emerald-300" : "text-destructive";
  const dotTone = chain.verified ? "bg-emerald-400" : "bg-destructive";

  return (
    <section className="redsim-sheet">
      <header className="redsim-sheet-label">
        <h2 className="m-0 break-all font-mono text-sm font-semibold">{chain.chain_id}</h2>
        <small className="redsim-sheet-note">
          length <span className="tabular-nums">{chain.event_count}</span>, head{" "}
          <span className="font-mono">{truncHash(chain.head_hash)}</span>
        </small>
        <span
          className={`mt-2 inline-flex items-center gap-1.5 text-xs font-medium ${statusTone}`}
          data-testid={`status-${chain.chain_id}`}
        >
          <i className={`redsim-dot ${dotTone}`} aria-hidden="true" />
          <span aria-hidden="true">{chain.verified ? "✓" : "✗"}</span>
          {chain.verified ? "verified" : "broken"}
        </span>
      </header>
      <div className="redsim-sheet-body space-y-3">

      {events.length > 0 ? (
        <div className="flex flex-wrap items-stretch gap-1 overflow-x-auto pb-1">
          {events.map((ev, idx) => {
            // A break point is the seq the API flagged, or the first event
            // whose prev_hash doesn't match the prior event's this_hash.
            const prior = events[idx - 1];
            const linkBroken =
              !chain.verified &&
              ((chain.broken_at != null && ev.seq === chain.broken_at) ||
                (prior != null && ev.prev_hash !== prior.this_hash));
            return (
              <div key={ev.seq} className="flex items-center">
                {idx > 0 && <ChainLink broken={linkBroken} />}
                <div className="flex flex-col items-center gap-1">
                  <span className="text-[10px] tabular-nums text-ink-3">
                    seq {ev.seq}
                  </span>
                  <HashNode
                    label="this"
                    hash={ev.this_hash}
                    broken={linkBroken}
                  />
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        // No per-event detail: render head as a single summary node.
        <div className="flex items-center gap-1">
          <HashNode
            label="head"
            hash={chain.head_hash}
            broken={!chain.verified}
          />
          {!chain.verified && (
            <span className="text-xs text-destructive">
              chain broken
              {chain.broken_at != null ? ` at seq ${chain.broken_at}` : ""}
            </span>
          )}
        </div>
      )}
      </div>
    </section>
  );
}

export default function AuditPage() {
  const authed = useRequireAuth();

  // The /v1/audit/verify endpoint walks every chain the writer knows.
  // Admin-only; non-admins get 403 from the API.
  const { data, error, isLoading } = useSWR(
    authed ? "/v1/audit/verify?all=1" : null,
    fetcher,
  );

  if (!authed)
    return <p className="text-ink-3">Signing in…</p>;
  if (isLoading)
    return <p className="text-ink-3">Verifying chains…</p>;
  if (error)
    return (
      <p className="rounded-[4px] border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
        Failed to verify: {String(error)}
      </p>
    );

  const chains = data?.chains ?? [];
  const allVerified = chains.length > 0 && chains.every((c) => c.verified);
  const brokenCount = chains.filter((c) => !c.verified).length;

  return (
    <TooltipProvider>
      <div className="space-y-6">
        <header className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1>Audit chains</h1>
            <p className="mt-1 max-w-[60ch] text-sm text-ink-3">
              Every project + run carries an append-only hash-chained audit.
              Each block below is one event linked to its predecessor.
            </p>
          </div>
          {chains.length > 0 && (
            <span
              data-testid="overall-status"
              className={`inline-flex items-center gap-2 text-sm font-medium ${
                allVerified ? "text-emerald-300" : "text-destructive"
              }`}
            >
              <i
                className={`redsim-dot ${allVerified ? "bg-emerald-400" : "bg-destructive"}`}
                aria-hidden="true"
              />
              <span aria-hidden="true">{allVerified ? "✓" : "✗"}</span>
              {allVerified
                ? "All chains verified"
                : `${brokenCount} chain${brokenCount === 1 ? "" : "s"} broken`}
            </span>
          )}
        </header>

        {chains.length === 0 ? (
          <p className="text-ink-3">No audit chains found.</p>
        ) : (
          <div>
            {chains.map((c) => (
              <ChainCard key={c.chain_id} chain={c} />
            ))}
          </div>
        )}
      </div>
    </TooltipProvider>
  );
}
