"use client";

// useRunEvents — subscribe to a run's live job-lifecycle events.
//
// The worker publishes one frame per job transition over the WS endpoint
// GET /v1/runs/{run_id}/events (redsim/api/ws.py):
//
//   { "type": "job", "run_id": "<id>", "job_id": "<id>",
//     "status": "running" | "succeeded" | "failed" }
//
// When no broker is configured the server emits periodic
// { "type": "heartbeat" } frames, which we ignore.
//
// This hook drives *liveness*: it invokes `onJob` on every job frame so the
// caller can revalidate its own data (typically SWR's mutate()). It does not
// fetch or shape status itself — the existing SWR data path stays the single
// source of truth, with a slow poll as the fallback when the socket is down.
//
// Auth mirrors the api() client (src/lib/api.ts): the redsim_api_session cookie
// rides the upgrade automatically, and a programmatic bearer token (localStorage
// redsim_token) is offered via the `redsim.bearer.<token>` subprotocol, which the
// server echoes back (RFC 6455).

import { useEffect, useRef } from "react";

import { apiWsBase, bearerToken } from "@/lib/api";

const BEARER_SUBPROTOCOL_PREFIX = "redsim.bearer.";

export type JobEvent = {
  type: "job";
  run_id: string;
  job_id: string;
  status: "running" | "succeeded" | "failed";
};

function isJobEvent(value: unknown): value is JobEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { type?: unknown }).type === "job"
  );
}

/**
 * Open a WebSocket to the run's events stream for the lifetime of the calling
 * component and call `onJob` for every `{ type: "job", … }` frame. Heartbeats,
 * malformed frames, and any other message types are ignored. No-ops (opens no
 * socket) when `runId` is falsy or when there is no `window` (SSR / tests
 * without a WebSocket global).
 */
export function useRunEvents(
  runId: string | null | undefined,
  onJob: (event: JobEvent) => void,
): void {
  // Keep the latest callback in a ref so the socket only re-subscribes when
  // `runId` changes — callers pass an inline closure (e.g. () => mutate()) and
  // we don't want a new render to tear down and reopen a live connection.
  const onJobRef = useRef(onJob);
  onJobRef.current = onJob;

  useEffect(() => {
    if (!runId) return;
    if (typeof window === "undefined" || typeof WebSocket === "undefined") {
      return;
    }

    const url = `${apiWsBase}/v1/runs/${runId}/events`;
    const token = bearerToken();
    let ws: WebSocket;
    try {
      ws = token
        ? new WebSocket(url, [`${BEARER_SUBPROTOCOL_PREFIX}${token}`])
        : new WebSocket(url);
    } catch {
      // Construction can throw (bad URL, hardened environments). Fall back to
      // the SWR poll silently rather than crashing the page.
      return;
    }

    ws.onmessage = (msg: MessageEvent) => {
      try {
        const evt: unknown = JSON.parse(String(msg.data));
        if (isJobEvent(evt)) onJobRef.current(evt);
      } catch {
        // Non-JSON / heartbeat frame — nothing to do.
      }
    };

    return () => {
      try {
        ws.close();
      } catch {
        /* already closed */
      }
    };
  }, [runId]);
}
