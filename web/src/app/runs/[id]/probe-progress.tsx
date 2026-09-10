"use client";

// ProbeProgress: the "prompts sent" bar of an LLM probe run.
//
// The worker writes stage_table.progress on every snapshot the garak child
// reports (redsim/workers/tasks/ml_llm.py); the page reads it from
// GET /v1/runs/{id}, which it already polls every 5 s while the run is
// active and revalidates on a job frame. There is no live frame for it: the
// persisted block is the only transport, so the bar is at most one poll
// behind. percent is 0..99 while the child runs and 100 only on success; on
// any other end the block keeps its last count and the status badge beside
// the bar carries the state.
//
// This is an operational count, never a measurement: nothing here reads as a
// score or a pass rate, and the block never enters a scorecard or a finding.

import { useEffect, useState } from "react";

/** `stage_table.progress` as the probe task writes it (counts and a short probe id only). */
export type ProgressBlock = {
  unit: string;
  done: number;
  total: number;
  percent: number;
  probe: string | null;
  probes_done: number;
  n_probes: number;
  updated_at: string;
};

const ACTIVE_RUN = new Set(["queued", "running"]);

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/**
 * The progress block of a run detail's `stage_table`, or `null` when the key
 * is absent or does not have the worker's shape (a campaign run, an older
 * row, a malformed value). The percent is clamped to 0..100 for the bar.
 */
export function readProgressBlock(
  stageTable: Record<string, unknown> | null | undefined,
): ProgressBlock | null {
  const raw = stageTable?.progress;
  if (typeof raw !== "object" || raw === null) return null;
  const block = raw as Record<string, unknown>;
  if (
    typeof block.unit !== "string" ||
    !isCount(block.done) ||
    !isCount(block.total) ||
    !isCount(block.percent) ||
    !isCount(block.probes_done) ||
    !isCount(block.n_probes) ||
    typeof block.updated_at !== "string" ||
    (block.probe != null && typeof block.probe !== "string")
  ) {
    return null;
  }
  return {
    unit: block.unit,
    done: block.done,
    total: block.total,
    percent: Math.max(0, Math.min(100, block.percent)),
    probe: typeof block.probe === "string" ? block.probe : null,
    probes_done: block.probes_done,
    n_probes: block.n_probes,
    updated_at: block.updated_at,
  };
}

/** Whole seconds between the block's stamp and `now`, clamped at 0; `null` for an unreadable stamp. */
export function ageSeconds(updatedAt: string, now: number): number | null {
  const stamp = Date.parse(updatedAt);
  if (Number.isNaN(stamp)) return null;
  return Math.max(0, Math.round((now - stamp) / 1000));
}

export type ProbeProgressProps = {
  block: ProgressBlock | null;
  /** Run status from GET /v1/runs/{id}; the age ticks only while the run is active. */
  runStatus?: string | null;
  /** Pins the clock (ms since the epoch) so a test can assert the age. */
  now?: number;
};

export function ProbeProgress({ block, runStatus, now }: ProbeProgressProps) {
  const active = !runStatus || ACTIVE_RUN.has(runStatus);
  const [clock, setClock] = useState<number>(() => now ?? Date.now());
  useEffect(() => {
    if (now !== undefined) {
      setClock(now);
      return;
    }
    setClock(Date.now());
    if (!active) return;
    // SWR skips the re-render when the poll returns an identical block, so
    // the age has to advance on its own for a hung child to look hung.
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [now, active, block?.updated_at]);

  if (!block) return null;
  const age = ageSeconds(block.updated_at, clock);
  const label = block.unit === "prompts" ? "prompts sent" : block.unit;
  const caption = [
    `${label} ${block.done} of ${block.total}`,
    block.probe ? `probe ${block.probe}` : null,
    age === null ? null : `updated ${age} s ago`,
  ]
    .filter((part) => part !== null)
    .join(" · ");
  return (
    <div className="mt-2 max-w-md" data-testid="probe-progress">
      <div
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={block.percent}
        className="h-1.5 w-full overflow-hidden rounded-sm bg-muted"
      >
        <div
          className="h-full bg-primary transition-[width] duration-500"
          style={{ width: `${block.percent}%` }}
        />
      </div>
      <p className="redsim-meta mt-1">{caption}</p>
    </div>
  );
}
