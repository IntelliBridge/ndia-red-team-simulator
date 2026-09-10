import "server-only";

import { env } from "@/env";

import type { ChatMessage } from "./context";

/**
 * The web process's Pythia client, for the finding chat.
 *
 * The same wire contract `redsim/llm/pythia.py` documents: `POST
 * {base}/v1/chat/completions` with `Authorization: Bearer pk_…` and an
 * optional `X-Pythia-Persona`, model ids canonical `<vendor>/<model>`. This
 * client adds `stream: true` and reads the server-sent events back as text
 * deltas. A gateway that answers a plain JSON completion instead is read as
 * one delta, so the route works against either.
 *
 * Nothing here logs the key, the URL, a message or a response body. TLS runs
 * on Node's trust store; behind a corporate proxy the host needs
 * `NODE_EXTRA_CA_CERTS` (docs/ops/pythia.md).
 */

export const CHAT_PATH = "/v1/chat/completions";

export type GatewaySettings = {
  baseUrl: string;
  apiKey: string;
  persona: string | null;
  timeoutMs: number;
  model: string;
};

/** The settings, or `null` when the process holds no gateway URL or key. */
export function gatewaySettings(): GatewaySettings | null {
  const baseUrl = env.PYTHIA_BASE_URL?.replace(/\/+$/, "");
  const apiKey = env.PYTHIA_API_KEY;
  if (!baseUrl || !apiKey) return null;
  return {
    baseUrl,
    apiKey,
    persona: env.PYTHIA_PERSONA ?? null,
    timeoutMs: env.PYTHIA_TIMEOUT_S * 1000,
    model: env.REDSIM_WEB_CHAT_MODEL,
  };
}

export type GatewayRefusalCode = "gateway_unreachable" | "gateway_timeout" | "gateway_error";

export type GatewayOpen =
  | { ok: true; model: string; deltas: AsyncIterable<string> }
  | { ok: false; code: GatewayRefusalCode; status: number };

/** Raised inside the delta stream when the gateway sends an error event or cuts the body. */
export class GatewayStreamError extends Error {
  constructor(readonly code: "gateway_stream_error" | "gateway_timeout") {
    super(code);
    this.name = "GatewayStreamError";
  }
}

/** Sampling settings, fixed: a reading assistant, not a writer. */
const TEMPERATURE = 0.2;
const MAX_TOKENS = 1200;

/**
 * Open one streamed chat completion.
 *
 * The abort signal covers the whole exchange, first byte to last: the client
 * closing the panel or the deadline passing ends the read. A non-2xx answer
 * is reported by status only; the gateway's body may echo the request and is
 * never forwarded.
 */
export async function openChatStream(
  settings: GatewaySettings,
  messages: ChatMessage[],
  signal: AbortSignal,
): Promise<GatewayOpen> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${settings.apiKey}`,
    "Content-Type": "application/json",
    Accept: "text/event-stream, application/json",
  };
  if (settings.persona) headers["X-Pythia-Persona"] = settings.persona;

  let response: Response;
  try {
    response = await fetch(`${settings.baseUrl}${CHAT_PATH}`, {
      method: "POST",
      headers,
      cache: "no-store",
      body: JSON.stringify({
        model: settings.model,
        messages,
        stream: true,
        temperature: TEMPERATURE,
        max_tokens: MAX_TOKENS,
      }),
      signal,
    });
  } catch (cause) {
    const timedOut =
      signal.aborted || (cause instanceof Error && (cause.name === "TimeoutError" || cause.name === "AbortError"));
    return { ok: false, code: timedOut ? "gateway_timeout" : "gateway_unreachable", status: timedOut ? 504 : 503 };
  }
  if (!response.ok) {
    return { ok: false, code: "gateway_error", status: response.status };
  }
  const contentType = (response.headers.get("content-type") ?? "").toLowerCase();
  if (contentType.includes("text/event-stream") && response.body) {
    return { ok: true, model: settings.model, deltas: sseDeltas(response.body, signal) };
  }
  return { ok: true, model: settings.model, deltas: jsonDelta(response, signal) };
}

/** The text of a completion chunk, streamed or whole. */
export function deltaText(chunk: unknown): string | null {
  const choice = (chunk as { choices?: Array<Record<string, unknown>> } | null)?.choices?.[0];
  if (!choice) return null;
  const delta = choice.delta as { content?: unknown } | undefined;
  if (typeof delta?.content === "string") return delta.content;
  const message = choice.message as { content?: unknown } | undefined;
  if (typeof message?.content === "string") return message.content;
  return null;
}

/** Whether a parsed event is the gateway reporting an error mid-stream. */
function isErrorEvent(chunk: unknown): boolean {
  return typeof chunk === "object" && chunk !== null && "error" in chunk && !("choices" in chunk);
}

/**
 * Parse `data:` lines out of a server-sent-event body and yield the content
 * deltas. `[DONE]` ends the stream. A malformed line is skipped; an `error`
 * event or a body cut before `[DONE]` raises `GatewayStreamError`.
 */
export async function* sseDeltas(
  body: ReadableStream<Uint8Array>,
  signal?: AbortSignal,
): AsyncGenerator<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let done = false;
  try {
    while (!done) {
      const { value, done: finished } = await reader.read();
      if (finished) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary = buffer.indexOf("\n\n");
      while (boundary !== -1) {
        const event = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        boundary = buffer.indexOf("\n\n");
        const data = event
          .split("\n")
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).trimStart())
          .join("\n");
        if (!data) continue;
        if (data === "[DONE]") {
          done = true;
          break;
        }
        let parsed: unknown;
        try {
          parsed = JSON.parse(data);
        } catch {
          continue;
        }
        if (isErrorEvent(parsed)) throw new GatewayStreamError("gateway_stream_error");
        const text = deltaText(parsed);
        if (text) yield text;
      }
    }
    if (!done && !buffer.trim() && signal?.aborted) throw new GatewayStreamError("gateway_timeout");
  } catch (cause) {
    if (cause instanceof GatewayStreamError) throw cause;
    throw new GatewayStreamError(signal?.aborted ? "gateway_timeout" : "gateway_stream_error");
  } finally {
    reader.releaseLock();
  }
}

/** A gateway that ignored `stream: true`: one JSON completion, one delta. */
async function* jsonDelta(response: Response, signal?: AbortSignal): AsyncGenerator<string> {
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    throw new GatewayStreamError(signal?.aborted ? "gateway_timeout" : "gateway_stream_error");
  }
  if (isErrorEvent(parsed)) throw new GatewayStreamError("gateway_stream_error");
  const text = deltaText(parsed);
  if (text) yield text;
}
