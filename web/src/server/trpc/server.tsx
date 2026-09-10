import "server-only";

import * as React from "react";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import {
  HydrationBoundary,
  dehydrate,
  type FetchQueryOptions,
  type QueryClient,
  type QueryKey,
} from "@tanstack/react-query";
import { createTRPCOptionsProxy } from "@trpc/tanstack-react-query";

import { env } from "@/env";
import { upstreamError } from "@/lib/api";
import type { UpstreamErrorData } from "@/lib/trpc/types";
import { makeQueryClient } from "@/lib/trpc/query-client";
import { mintHopToken } from "@/server/gate";

import {
  createContext,
  requestPartsFromNextHeaders,
  type CookieReader,
  type RequestParts,
} from "./context";
import { badRequestEnvelope } from "./errors";
import { appRouter } from "./root";

/**
 * Per-request memoization.
 *
 * Next supplies `React.cache` in the app-router server runtime. Stable React
 * 18.3.1 exports none, and the identity fallback this used to carry was a live
 * wrong answer rather than a safe one: with it, `prefetch` and `HydrateClient`
 * each got their own QueryClient, so the page dehydrated an empty cache and
 * shipped HTML with nothing behind it.
 *
 * Failing at import is the safe direction. A module-scoped memo would make the
 * two agree, but it would share one QueryClient across requests, which in this
 * app means one user's rows reaching another. A plain Node import supplies
 * `cache` instead; the server-component tests already do.
 */
if (typeof React.cache !== "function") {
  throw new Error(
    "React.cache is required for per-request memoization. Next supplies it in " +
      "the app-router server runtime, and a plain Node import has to provide it.",
  );
}
const memoize: <T>(fn: () => T) => () => T = React.cache;

/** One QueryClient per request. Never shared across users. */
export const getQueryClient = memoize<QueryClient>(() => makeQueryClient());

/**
 * The one place this module reads Next's request APIs.
 *
 * `cookies()` and `headers()` are synchronous on Next 14.2 and become async in
 * Next 15. Everything here goes through `requestPartsFromNextHeaders`, so that
 * function and this one are the whole surface the six-major bump touches.
 */
function serverRequestParts(): RequestParts {
  return requestPartsFromNextHeaders(headers(), cookies());
}

/** The context a server component calls procedures with. */
export function createServerContext() {
  return createContext(serverRequestParts());
}

/** The options proxy server components prefetch through. */
export const trpcServer = createTRPCOptionsProxy({
  ctx: createServerContext,
  router: appRouter,
  queryClient: getQueryClient,
});

/**
 * Strip a procedure error down to what may cross the RSC boundary.
 *
 * The server options proxy calls procedures directly, so the HTTP error
 * formatter never runs here and whatever is dehydrated is serialized as its
 * own enumerable properties. A TRPCError would carry a name and, on a network
 * failure, a cause naming the API host. This returns a plain object literal:
 * no prototype beyond Object, no cause, no stack (KTD4).
 *
 * A schema failure is the one error that reaches here with no envelope: the
 * `.input()` parser runs after `withRequestId`, so the error carries the
 * request id and nothing else. It goes through `badRequestEnvelope`, the same
 * helper the HTTP error formatter uses, rather than falling through to the
 * generic 500: a user whose input was refused sees the 400 and the field
 * issues, not `upstream_error`.
 */
export function toBrowserSafeError(error: unknown): { data: UpstreamErrorData } {
  const upstream = upstreamError(error);
  const requestId = (error as { data?: { requestId?: unknown } } | null)?.data?.requestId;
  const validation =
    upstream === undefined && (error as { code?: unknown } | null)?.code === "BAD_REQUEST"
      ? badRequestEnvelope(error as { message?: unknown; cause?: unknown })
      : undefined;
  return {
    data: {
      ...(validation?.input ? { input: validation.input } : {}),
      upstream:
        upstream ??
        validation?.upstream ?? {
          status: 500,
          code: "upstream_error",
          message: "the request could not be completed",
        },
      requestId: typeof requestId === "string" ? requestId : "",
    },
  };
}

/**
 * The credential the prefetch forwarded, so the hop token can bind to it.
 *
 * Takes the reader rather than calling `cookies()` itself, so this module has
 * exactly one site that touches Next's request APIs.
 *
 * @param cookie - The request's cookie lookup, from `serverRequestParts`.
 * @returns The session cookie, else the dev token, else undefined.
 */
function rejectedCredential(cookie: CookieReader): string | undefined {
  return cookie(env.REDSIM_API_SESSION_COOKIE);
}

/**
 * Where a 401 from an awaited prefetch sends the browser.
 *
 * A rejected cookie has to be cleared before /login renders, because the
 * middleware gate checks presence alone and would bounce straight back. With
 * no credential at all there is nothing to clear and nothing to bind a hop
 * token to, so that case goes to /login directly. This is the shape between
 * U1 and U7, where no middleware exists yet and an anonymous page load reaches
 * the prefetch with an empty cookie jar.
 */
export async function unauthorizedRedirectTarget(): Promise<string> {
  const credential = rejectedCredential(serverRequestParts().cookie);
  if (credential === undefined) return "/login";
  const token = await mintHopToken(env.REDSIM_WEB_SESSION_SECRET ?? "", credential);
  return `/api/auth/signout-redsim?hop=${encodeURIComponent(token)}`;
}

/**
 * Prefetch one query into the request's QueryClient and await it.
 *
 * Awaiting is deliberate: the first HTML then carries every key the page
 * prefetched, `loading.tsx` covers the whole await, and no client leaf has to
 * keep a loading branch for a key that hydrated (R9). A failure is not a
 * throw: the error is dehydrated with the data so the leaf mounts with its
 * honest state already rendered.
 *
 * Generic over the options the tRPC options proxy hands it, rather than taking
 * one widened shape: the proxy's `staleTime` callback is typed against the
 * procedure's own output and error, and a widened parameter is not assignable
 * to it.
 */
export async function prefetch<TQueryFnData, TError, TData, TQueryKey extends QueryKey>(
  options: FetchQueryOptions<TQueryFnData, TError, TData, TQueryKey>,
): Promise<void> {
  const queryClient = getQueryClient();
  const queryFn = options.queryFn;

  await queryClient.prefetchQuery({
    ...options,
    queryFn:
      typeof queryFn === "function"
        ? async (context) => {
            try {
              return await queryFn(context);
            } catch (error) {
              throw toBrowserSafeError(error);
            }
          }
        : queryFn,
  });

  const state = queryClient.getQueryState(options.queryKey);
  if (state?.status === "error" && upstreamError(state.error)?.status === 401) {
    // Not dehydrated: the browser is sent to clear the rejected cookie first.
    redirect(await unauthorizedRedirectTarget());
  }
}

/** One hydration boundary per page (KTD4). */
export function HydrateClient({ children }: { children: React.ReactNode }) {
  return (
    <HydrationBoundary state={dehydrate(getQueryClient())}>{children}</HydrationBoundary>
  );
}
