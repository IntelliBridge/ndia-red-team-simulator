// A stand-in for FastAPI, shared by the server-side and client-side helpers.
//
// Server-component and route tests run in the node environment and stub the
// global fetch, so the real context, the real upstream wrapper and the real
// error formatter all run over these answers. Client-leaf tests run in jsdom,
// where a server module cannot be imported at all (the env module throws on a
// server-variable read once a window exists), so they feed the tRPC link the
// wire envelope instead. Both routes derive their codes from the one status
// map in the upstream wrapper, so a test can never assert a code the layer
// would not produce.

import { synthesizedCodeForStatus, trpcCodeForStatus } from "@/server/trpc/upstream";
import type { UpstreamErrorBlock } from "@/lib/trpc/types";

export type UpstreamAnswer =
  | { kind: "json"; status: number; body: unknown }
  | { kind: "network-error"; message: string };

/** `{ detail }` as FastAPI writes it, with either envelope shape. */
export function detailBody(detail: string | Record<string, unknown>): { detail: unknown } {
  return { detail };
}

/** One recorded outbound call. */
export type UpstreamCall = { url: string; method: string; headers: Record<string, string> };

/**
 * A queue-free fetch stub: every call gets the current answer.
 *
 * Deliberately not a one-shot queue. The poll and retry assertions care about
 * how many calls happened, not about varying the answer per call, and a fresh
 * Response is built each time because a body can only be read once.
 */
export class MockUpstream {
  answer: UpstreamAnswer = { kind: "json", status: 200, body: {} };
  readonly calls: UpstreamCall[] = [];

  /** Answer every call with this JSON status and body. */
  json(status: number, body: unknown): this {
    this.answer = { kind: "json", status, body };
    return this;
  }

  /** Reject every call, as an unreachable API does. */
  networkError(message: string): this {
    this.answer = { kind: "network-error", message };
    return this;
  }

  /** The function to install as the global fetch. */
  readonly fetch = (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    this.calls.push({
      url: String(input),
      method: (init?.method ?? "GET").toUpperCase(),
      headers: { ...((init?.headers as Record<string, string> | undefined) ?? {}) },
    });
    if (this.answer.kind === "network-error") {
      return Promise.reject(new Error(this.answer.message));
    }
    return Promise.resolve(
      new Response(JSON.stringify(this.answer.body), {
        status: this.answer.status,
        headers: { "content-type": "application/json" },
      }),
    );
  };
}

// --- The jsdom side: tRPC wire envelopes -------------------------------------

/** The envelope a successful batched call returns. */
export function trpcResult(data: unknown): unknown {
  return { result: { data } };
}

/**
 * The envelope the error formatter produces for an API refusal.
 *
 * Built from the same status map the wrapper uses, so a leaf test asserting on
 * `upstream.code` is asserting on the code the layer really emits.
 */
export function trpcUpstreamError(
  status: number,
  overrides: Partial<UpstreamErrorBlock> = {},
  requestId = "0123456789abcdef0123456789abcdef",
): unknown {
  const upstream: UpstreamErrorBlock = {
    status,
    code: synthesizedCodeForStatus(status),
    message: `API responded ${status}`,
    ...overrides,
  };
  return {
    error: {
      message: upstream.message,
      code: -32603,
      data: { code: trpcCodeForStatus(status), upstream, requestId },
    },
  };
}
