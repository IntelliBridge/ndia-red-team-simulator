// The browser side of the finding chat.
//
// Talks to the web app's own route, /api/chat/finding, never to FastAPI or
// the gateway. The route streams newline-delimited JSON events; this module
// reads them, keeps the conversation in sessionStorage per finding, and
// writes the example prompts from the finding's own terms.

import type { Finding } from "@/lib/api";

export const CHAT_ROUTE = "/api/chat/finding";

export type ChatRole = "user" | "assistant";

export type ChatTurn = {
  id: string;
  role: ChatRole;
  content: string;
  /** Set on an assistant turn the stream could not finish. */
  error?: string | null;
};

export type ChatStreamEvent =
  | { type: "meta"; model: string; request_id: string }
  | { type: "delta"; text: string }
  | { type: "done" }
  | { type: "error"; code: string; message: string };

export type ChatStatus = { configured: boolean; model: string | null };

/** A refusal the route answered before the stream started. */
export class ChatError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ChatError";
  }
}

/** What the panel says for each refusal code. */
export function describeChatError(error: unknown): string {
  if (error instanceof ChatError) {
    switch (error.code) {
      case "llm_not_configured":
        return "Chat is unavailable. The web server holds no Pythia gateway settings.";
      case "unauthenticated":
        return "Your session ended. Sign in again to continue.";
      case "forbidden":
        return "Access denied for this finding.";
      case "not_found":
        return "Finding not found.";
      case "gateway_unreachable":
        return "The gateway could not be reached. Try again in a moment.";
      case "gateway_timeout":
        return "The gateway did not answer in time.";
      case "gateway_error":
        return `The gateway refused the request (${error.status}).`;
      default:
        return `${error.status}: ${error.message}`;
    }
  }
  if (error instanceof DOMException && error.name === "AbortError") return "Stopped.";
  return "The chat request failed. Try again.";
}

async function refusalFrom(response: Response): Promise<ChatError> {
  let code = "upstream_error";
  let message = `chat route answered ${response.status}`;
  try {
    const body = (await response.json()) as { code?: unknown; message?: unknown };
    if (typeof body.code === "string") code = body.code;
    if (typeof body.message === "string") message = body.message;
  } catch {
    // A body that is not JSON keeps the status-only message.
  }
  return new ChatError(response.status, code, message);
}

/** Whether the web server can answer a chat at all, and with which model. */
export async function fetchChatStatus(): Promise<ChatStatus> {
  const response = await fetch(CHAT_ROUTE, { method: "GET", credentials: "same-origin", cache: "no-store" });
  if (!response.ok) throw await refusalFrom(response);
  return (await response.json()) as ChatStatus;
}

/**
 * Send the conversation and yield the route's events as they arrive.
 *
 * The history is the whole visible conversation, so the server holds no
 * session: the route is stateless and the browser is the record.
 */
export async function* streamFindingChat(
  findingId: string,
  history: Array<{ role: ChatRole; content: string }>,
  signal?: AbortSignal,
): AsyncGenerator<ChatStreamEvent> {
  const response = await fetch(CHAT_ROUTE, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "Content-Type": "application/json", Accept: "application/x-ndjson" },
    body: JSON.stringify({ finding_id: findingId, messages: history }),
    signal,
  });
  if (!response.ok) throw await refusalFrom(response);
  if (!response.body) throw new ChatError(502, "empty_stream", "the chat route sent no body");
  yield* readNdjson(response.body);
}

/** Parse newline-delimited JSON events out of a byte stream. */
export async function* readNdjson(body: ReadableStream<Uint8Array>): AsyncGenerator<ChatStreamEvent> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let newline = buffer.indexOf("\n");
      while (newline !== -1) {
        const lineText = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        newline = buffer.indexOf("\n");
        if (lineText) yield parseEvent(lineText);
      }
    }
    const tail = buffer.trim();
    if (tail) yield parseEvent(tail);
  } finally {
    reader.releaseLock();
  }
}

function parseEvent(text: string): ChatStreamEvent {
  try {
    const parsed = JSON.parse(text) as ChatStreamEvent;
    if (parsed && typeof parsed === "object" && typeof parsed.type === "string") return parsed;
  } catch {
    // Fall through to the error event.
  }
  return { type: "error", code: "bad_event", message: "the chat stream sent an unreadable event" };
}

// ── Example prompts ─────────────────────────────────────────────────

/**
 * Starter questions in the finding's own terms.
 *
 * Every prompt asks for something the recorded context can answer with its
 * labels intact: measurements with denominators, candidates as candidates,
 * limitations. None asks for advice on fielding the model.
 */
export function examplePrompts(finding: Finding): string[] {
  const ml = finding.schema_blob?.ml ?? null;
  const attack = ml?.attack_name ?? ml?.attack_id ?? finding.schema_blob?.attack_id ?? "the attack";
  const eps = ml?.reference_eps;
  const atEps = typeof eps === "number" ? ` at ε = ${eps}` : "";
  const severity = finding.severity ? `${finding.severity} ` : "";
  return [
    "Explain this finding in plain language for a reviewer who has not seen the campaign.",
    `Which measurements support the ${severity}severity, and what are their denominators?`,
    `How does the noise control compare with ${attack}${atEps}?`,
    "Which candidate recommendations apply here, and what evidence triggered each of them?",
    "What limitations should I cite before I act on this finding?",
    "What does the explanation shift show, and what does it not show?",
  ];
}

// ── Per-finding conversation storage ────────────────────────────────

export const CHAT_STORAGE_PREFIX = "redsim.chat.";

function storage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.sessionStorage;
  } catch {
    return null;
  }
}

export function loadConversation(findingId: string): ChatTurn[] {
  try {
    const raw = storage()?.getItem(`${CHAT_STORAGE_PREFIX}${findingId}`);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (turn): turn is ChatTurn =>
        typeof turn === "object" &&
        turn !== null &&
        typeof (turn as ChatTurn).id === "string" &&
        ((turn as ChatTurn).role === "user" || (turn as ChatTurn).role === "assistant") &&
        typeof (turn as ChatTurn).content === "string",
    );
  } catch {
    return [];
  }
}

export function saveConversation(findingId: string, turns: ChatTurn[]): void {
  try {
    const store = storage();
    if (!store) return;
    const key = `${CHAT_STORAGE_PREFIX}${findingId}`;
    if (turns.length === 0) store.removeItem(key);
    else store.setItem(key, JSON.stringify(turns));
  } catch {
    // A full or blocked store loses the transcript, nothing else.
  }
}

export function newTurnId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
