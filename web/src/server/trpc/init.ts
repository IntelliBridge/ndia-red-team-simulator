import "server-only";

import { initTRPC } from "@trpc/server";

import { env } from "@/env";
import type { UpstreamErrorData } from "@/lib/trpc/types";

import { beginCall, type TrpcContext } from "./context";
import { badRequestEnvelope } from "./errors";
import { checkMutationRequest } from "./mutation-gate";
import { UpstreamTRPCError } from "./upstream";

const t = initTRPC.context<TrpcContext>().create({
  /**
   * Copy the envelope the wrapper already attached rather than rebuilding it,
   * so the HTTP path and the server prefetch path carry the identical shape
   * (KTD4, KTD8).
   *
   * A schema failure never reaches the upstream, so nothing is attached to it.
   * `badRequestEnvelope` supplies the 400 block and the grouped field issues,
   * and the server prefetch path calls the same helper: a validation refusal
   * therefore reads the same on both paths rather than arriving as a generic
   * 500 on one of them. An upstream 400 already carries its own envelope and
   * keeps it.
   */
  errorFormatter({ shape, error }) {
    const attached = (error as { data?: UpstreamErrorData }).data;
    const validation =
      error.code === "BAD_REQUEST" && attached?.upstream === undefined
        ? badRequestEnvelope(error)
        : undefined;
    const data = {
      ...shape.data,
      ...(attached ?? {}),
      ...(validation ?? {}),
    };
    if (process.env.NODE_ENV === "production" && "stack" in data) delete data.stack;
    return { ...shape, data };
  },
});

export const router = t.router;
export const createCallerFactory = t.createCallerFactory;

/**
 * Mint this call's request id, record it for the response header, and make
 * sure it reaches the caller even when the call never touched the upstream.
 *
 * A schema failure is refused before any upstream call, so it carries no
 * envelope; it still carries the id, because R3 wants an id a user can quote
 * for every call, not only for calls the API answered.
 */
const withRequestId = t.middleware(async ({ ctx, next }) => {
  const called = beginCall(ctx);
  const result = await next({ ctx: called });
  if (!result.ok) {
    const error = result.error as { data?: Partial<UpstreamErrorData> };
    error.data = { ...(error.data ?? {}), requestId: called.requestId };
  }
  return result;
});

/** Every procedure. Authorization stays with the API (KD5, R12). */
export const publicProcedure = t.procedure.use(withRequestId);

/**
 * A procedure that changes something upstream.
 *
 * The gate runs before any upstream call, so a cross-site or same-site sender
 * never reaches FastAPI. `BETTER_AUTH_URL` is optional at build time, and an
 * absent value fails the Origin comparison closed.
 */
export const mutationProcedure = publicProcedure.use(({ ctx, next }) => {
  const verdict = checkMutationRequest({
    secFetchSite: ctx.secFetchSite,
    origin: ctx.origin,
    contentType: ctx.contentType,
    acceptedContentType: "application/json",
    trustedOrigin: env.BETTER_AUTH_URL ?? "",
  });
  if (!verdict.ok) {
    throw new UpstreamTRPCError("FORBIDDEN", {
      upstream: {
        status: 403,
        code: "forbidden",
        message: "this request did not come from the redsim web app",
        refusal_reason: verdict.reason,
      },
      requestId: ctx.requestId,
    });
  }
  return next();
});
