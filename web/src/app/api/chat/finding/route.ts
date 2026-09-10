import { z } from "zod";

import { env } from "@/env";
import type { Campaign, Finding } from "@/lib/api";
import { buildMessages, type HistoryTurn } from "@/server/chat/context";
import { gatewaySettings, GatewayStreamError, openChatStream } from "@/server/chat/pythia";
import { beginCall, createContext, requestPartsFromRequest } from "@/server/trpc/context";
import { checkMutationRequest } from "@/server/trpc/mutation-gate";
import { idSchema } from "@/server/trpc/routers/runs";
import { upstreamFetch, UpstreamTRPCError } from "@/server/trpc/upstream";

/**
 * The finding chat.
 *
 * `GET` says whether the web process holds gateway settings and which model
 * it would send, so the panel can say "unavailable" before the analyst types.
 * `POST` fetches the finding and its campaign record from FastAPI with the
 * caller's own cookie, builds the prompt from those two records and streams
 * the gateway's answer back as newline-delimited JSON events.
 *
 * The browser never names the record's contents, only the finding id and its
 * own turns, so a user cannot ask about a finding the API would refuse them:
 * the refusal comes back with the API's status and code. The gateway key
 * stays in this process. No audit row and no `LLMUsage` row is written for a
 * turn; that gap is recorded under the README's open items.
 *
 * Same-origin only, through the tRPC layer's mutation gate rather than the
 * API's double-submit cookie, because this route lives on the web origin.
 */

export const dynamic = "force-dynamic";

const turnSchema = z.object({
  role: z.enum(["user", "assistant"]),
  content: z.string().min(1).max(8_000),
});

const bodySchema = z.object({
  finding_id: idSchema,
  messages: z
    .array(turnSchema)
    .min(1)
    .max(40)
    .refine((turns) => turns[turns.length - 1]?.role === "user", "the last turn must be the user's"),
});

/** The fields the prompt reads are optional on the record, so the parse only pins the identity. */
const findingSchema = z.looseObject({
  id: z.string(),
  run_id: z.string(),
  project_id: z.string(),
  severity: z.string(),
  status: z.string(),
  schema_blob: z.looseObject({}),
});

const campaignSchema = z.looseObject({
  run_id: z.string(),
  status: z.string(),
});

/** One NDJSON event as the panel reads it. */
export type ChatStreamEvent =
  | { type: "meta"; model: string; request_id: string }
  | { type: "delta"; text: string }
  | { type: "done" }
  | { type: "error"; code: string; message: string };

function json(status: number, body: unknown, requestId: string): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Redsim-Request-ID": requestId,
    },
  });
}

/** An API refusal, forwarded with the API's own status and envelope. */
function refusal(error: UpstreamTRPCError, requestId: string): Response {
  const { status, code, message } = error.data.upstream;
  return json(status, { code, message }, requestId);
}

export async function GET(request: Request): Promise<Response> {
  const ctx = beginCall(createContext(requestPartsFromRequest(request)));
  if (ctx.credential === null) {
    return json(401, { code: "unauthenticated", message: "sign in to continue" }, ctx.requestId);
  }
  const settings = gatewaySettings();
  return json(
    200,
    { configured: settings !== null, model: settings?.model ?? null },
    ctx.requestId,
  );
}

export async function POST(request: Request): Promise<Response> {
  const ctx = beginCall(createContext(requestPartsFromRequest(request)));

  const verdict = checkMutationRequest({
    secFetchSite: ctx.secFetchSite,
    origin: ctx.origin,
    contentType: ctx.contentType,
    acceptedContentType: "application/json",
    trustedOrigin: env.REDSIM_WEB_ORIGIN ?? "",
  });
  if (!verdict.ok) {
    return json(
      403,
      { code: "forbidden", message: "this request did not come from the redsim web app", refusal_reason: verdict.reason },
      ctx.requestId,
    );
  }
  if (ctx.credential === null) {
    return json(401, { code: "unauthenticated", message: "sign in to continue" }, ctx.requestId);
  }

  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return json(400, { code: "bad_request", message: "the body is not JSON" }, ctx.requestId);
  }
  const parsed = bodySchema.safeParse(raw);
  if (!parsed.success) {
    return json(400, { code: "bad_request", message: "the body does not match the chat request shape" }, ctx.requestId);
  }
  const { finding_id: findingId, messages: history } = parsed.data;

  const settings = gatewaySettings();
  if (settings === null) {
    return json(
      503,
      { code: "llm_not_configured", message: "the web server holds no Pythia gateway settings" },
      ctx.requestId,
    );
  }

  let finding: Finding;
  try {
    finding = (await upstreamFetch(ctx, { method: "GET", segments: ["v1", "findings", findingId] }, findingSchema)) as unknown as Finding;
  } catch (error) {
    if (error instanceof UpstreamTRPCError) return refusal(error, ctx.requestId);
    throw error;
  }

  // The campaign record is context, not a requirement: an LLM probe finding
  // answers 409 llm_target_required here and a run without a record 404, and
  // the chat still runs on the finding alone with the reason in the prompt.
  let campaign: Campaign | null = null;
  let campaignUnavailable: string | null = null;
  try {
    campaign = (await upstreamFetch(
      ctx,
      { method: "GET", segments: ["v1", "runs", finding.run_id, "campaign"] },
      campaignSchema,
    )) as unknown as Campaign;
  } catch (error) {
    if (!(error instanceof UpstreamTRPCError)) throw error;
    if (error.data.upstream.status === 401 || error.data.upstream.status === 403) return refusal(error, ctx.requestId);
    campaignUnavailable = error.data.upstream.code;
  }

  const messages = buildMessages({ finding, campaign, campaignUnavailable }, history as HistoryTurn[]);

  const controller = new AbortController();
  const deadline = AbortSignal.timeout(settings.timeoutMs);
  const onAbort = () => controller.abort();
  request.signal.addEventListener("abort", onAbort);
  deadline.addEventListener("abort", onAbort);

  const opened = await openChatStream(settings, messages, controller.signal);
  if (!opened.ok) {
    request.signal.removeEventListener("abort", onAbort);
    console.error(`finding chat gateway refused request_id=${ctx.requestId} code=${opened.code} status=${opened.status}`);
    return json(
      opened.status >= 500 && opened.status < 600 ? opened.status : 502,
      { code: opened.code, message: `the gateway answered ${opened.status}` },
      ctx.requestId,
    );
  }

  const encoder = new TextEncoder();
  const line = (event: ChatStreamEvent) => encoder.encode(`${JSON.stringify(event)}\n`);
  const stream = new ReadableStream<Uint8Array>({
    async start(sink) {
      // A browser that closed the panel cancels the stream; an enqueue after
      // that throws, and the gateway read is what has to stop, not the
      // handler. `push` therefore swallows the sink's own errors.
      const push = (event: ChatStreamEvent) => {
        try {
          sink.enqueue(line(event));
        } catch {
          controller.abort();
        }
      };
      push({ type: "meta", model: opened.model, request_id: ctx.requestId });
      try {
        for await (const text of opened.deltas) {
          if (controller.signal.aborted) break;
          push({ type: "delta", text });
        }
        push({ type: "done" });
      } catch (cause) {
        const code = cause instanceof GatewayStreamError ? cause.code : "gateway_stream_error";
        console.error(`finding chat stream failed request_id=${ctx.requestId} code=${code}`);
        push({
          type: "error",
          code,
          message: code === "gateway_timeout" ? "the gateway did not finish in time" : "the gateway stream ended with an error",
        });
      } finally {
        request.signal.removeEventListener("abort", onAbort);
        try {
          sink.close();
        } catch {
          // Already cancelled by the browser.
        }
      }
    },
    cancel() {
      controller.abort();
    },
  });

  return new Response(stream, {
    status: 200,
    headers: {
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Accel-Buffering": "no",
      "X-Redsim-Request-ID": ctx.requestId,
    },
  });
}
