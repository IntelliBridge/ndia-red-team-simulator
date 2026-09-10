// The browser side of the finding chat.
//
// Talks to the web app's own route, /api/chat/finding, never to FastAPI or
// the gateway. The route streams newline-delimited JSON events; this module
// reads them, keeps the conversation in sessionStorage per finding, and
// writes the example prompts from the finding's own terms.

import type { CampaignConfig, CampaignRequest, Finding } from "@/lib/api";

export const CHAT_ROUTE = "/api/chat/finding";

export type ChatRole = "user" | "assistant";

export type ChatTurn = {
  id: string;
  role: ChatRole;
  content: string;
  /** Set on an assistant turn the stream could not finish. */
  error?: string | null;
  /** The run the analyst started from this turn's proposal, once the API admitted it. */
  proposal_run_id?: string | null;
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
      case "attacks_unavailable":
        return "The attack catalog could not be read, so no campaign can be proposed right now.";
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

// ── Campaign proposals ──────────────────────────────────────────────
//
// The assistant may end an answer with one fenced block tagged
// `redsim-proposal` (server/chat/context.ts, rule 8). The block is a
// candidate campaign and nothing more: the analyst reads it, clicks Run, and
// the platform admits or refuses it through POST /v1/models/{id}/attacks with
// its own checks and its own audit row. Nothing here runs anything.

/** The language tag of the proposal block. Mirrors PROPOSAL_FENCE in server/chat/context.ts. */
export const PROPOSAL_FENCE = "redsim-proposal";

export const PROPOSAL_NORMS = ["linf", "l2", "edit", "patch_area"] as const;
export type ProposalNorm = (typeof PROPOSAL_NORMS)[number];

/** A candidate campaign as the assistant wrote it, after the shape check. */
export type CampaignProposal = {
  attack_ids: string[];
  norm: ProposalNorm;
  eps_grid: number[];
  reference_eps: number;
  n_samples: number;
  rationale: string;
};

/** An assistant turn split into its prose and its proposal, if any. */
export type ParsedTurn = {
  /** The answer with the proposal block removed. */
  text: string;
  proposal: CampaignProposal | null;
  /** Why a block that was present could not be used. */
  invalid: string | null;
  /** A block has been opened and not yet closed (the stream is still writing it). */
  pending: boolean;
};

const FENCE_OPEN = new RegExp("```" + PROPOSAL_FENCE + "[ \\t]*\\r?\\n");
const FENCE_CLOSE = /\r?\n?```/;

/** The admission's default grid limit (redsim.services.ml_campaigns DEFAULT_MAX_EPS_GRID_MEMBERS). */
const MAX_GRID = 3;
const MAX_N_SAMPLES = 500;

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/** Check a parsed block against the shape a campaign request can carry. */
export function validateProposal(raw: unknown): { proposal: CampaignProposal | null; invalid: string | null } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { proposal: null, invalid: "the proposal is not a JSON object" };
  }
  const doc = raw as Record<string, unknown>;
  const attackIds = doc.attack_ids;
  if (!Array.isArray(attackIds) || attackIds.length === 0 || !attackIds.every((id) => typeof id === "string" && id.length > 0)) {
    return { proposal: null, invalid: "attack_ids must be a non-empty list of attack ids" };
  }
  const uniqueIds = Array.from(new Set(attackIds as string[]));
  const norm = doc.norm;
  if (typeof norm !== "string" || !(PROPOSAL_NORMS as readonly string[]).includes(norm)) {
    return { proposal: null, invalid: `norm must be one of ${PROPOSAL_NORMS.join(", ")}` };
  }
  const grid = doc.eps_grid;
  if (!Array.isArray(grid) || grid.length === 0 || grid.length > MAX_GRID || !grid.every((eps) => isFiniteNumber(eps) && eps > 0)) {
    return { proposal: null, invalid: `eps_grid must be 1 to ${MAX_GRID} positive numbers` };
  }
  const sorted = [...(grid as number[])].sort((a, b) => a - b);
  if (new Set(sorted).size !== sorted.length) {
    return { proposal: null, invalid: "eps_grid must not repeat a value" };
  }
  const reference = doc.reference_eps;
  if (!isFiniteNumber(reference) || !sorted.includes(reference)) {
    return { proposal: null, invalid: "reference_eps must be a member of eps_grid" };
  }
  const n = doc.n_samples;
  if (!Number.isInteger(n) || (n as number) <= 0 || (n as number) > MAX_N_SAMPLES) {
    return { proposal: null, invalid: `n_samples must be an integer from 1 to ${MAX_N_SAMPLES}` };
  }
  const rationale = typeof doc.rationale === "string" ? doc.rationale.trim() : "";
  return {
    proposal: {
      attack_ids: uniqueIds,
      norm: norm as ProposalNorm,
      eps_grid: sorted,
      reference_eps: reference,
      n_samples: n as number,
      rationale,
    },
    invalid: null,
  };
}

/**
 * Split an assistant turn into prose and proposal.
 *
 * While the stream is still inside the block, `pending` is true and the
 * partial JSON is kept out of the prose so the reader never sees half a
 * proposal. A closed block that does not parse or does not validate leaves
 * `proposal` null with the reason in `invalid`; the prose is still shown.
 */
export function parseProposal(content: string): ParsedTurn {
  const open = FENCE_OPEN.exec(content);
  if (!open) return { text: content, proposal: null, invalid: null, pending: false };
  const before = content.slice(0, open.index).trimEnd();
  const rest = content.slice(open.index + open[0].length);
  const close = FENCE_CLOSE.exec(rest);
  if (!close) return { text: before, proposal: null, invalid: null, pending: true };
  const body = rest.slice(0, close.index).trim();
  const after = rest.slice(close.index + close[0].length).trim();
  const text = after ? `${before}\n\n${after}` : before;
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    return { text, proposal: null, invalid: "the proposal block is not valid JSON", pending: false };
  }
  const checked = validateProposal(raw);
  return { text, proposal: checked.proposal, invalid: checked.invalid, pending: false };
}

/** The keys the server owns and a request must never carry (redsim/services/ml_campaigns.py). */
const SERVER_OWNED = new Set(["target_id", "modality", "dataset_split", "scoring", "target_snapshot", "attacks", "attack_params"]);

/**
 * The request body for POST /v1/models/{id}/attacks: the recorded campaign's
 * settings with the proposal's attack set, norm, grid, reference and sample
 * count in place of the parent's. Attack params are not carried over, so the
 * adapters run on their per-modality defaults; the admission freezes what it
 * admits and refuses what it does not, and the panel shows that refusal.
 */
export function buildProposalRequest(config: CampaignConfig, proposal: CampaignProposal): CampaignRequest {
  const base: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(config)) {
    if (!SERVER_OWNED.has(key) && value !== undefined) base[key] = value;
  }
  return {
    ...(base as Partial<CampaignRequest>),
    dataset_id: config.dataset_id,
    attack_ids: proposal.attack_ids,
    norm: proposal.norm as CampaignRequest["norm"],
    eps_grid: proposal.eps_grid,
    reference_eps: proposal.reference_eps,
    n_samples: proposal.n_samples,
  };
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
    "What should I run next to narrow this finding? Propose a campaign.",
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
