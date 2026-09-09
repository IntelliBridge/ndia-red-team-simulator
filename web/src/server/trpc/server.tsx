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

import { createContext, requestPartsFromNextHeaders } from "./context";
import { appRouter } from "./root";

/**
 * Per-request memoization.
 *
 * Stable React 18.3.1 exports no `cache()` (only Next's bundled canary does),
 * so reading it unguarded would throw at import in every server-component
 * test. The identity fallback is correct but not shared: on this baseline each
 * caller in one render gets its own QueryClient, which is safe because no
 * instance is ever reused across requests. The guard goes away with React 19.
 */
const memoize: <T>(fn: () => T) => () => T =
  typeof React.cache === "function" ? React.cache : (fn) => fn;

/** One QueryClient per request. Never shared across users. */
export const getQueryClient = memoize<QueryClient>(() => makeQueryClient());

/**
 * The context a server component calls procedures with.
 *
 * `cookies()` and `headers()` are synchronous on Next 14.2. `requestParts…` is
 * the seam that changes when they become async.
 */
export function createServerContext() {
  return createContext(requestPartsFromNextHeaders(headers(), cookies()));
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
 */
export function toBrowserSafeError(error: unknown): { data: UpstreamErrorData } {
  const upstream = upstreamError(error);
  const requestId = (error as { data?: { requestId?: unknown } } | null)?.data?.requestId;
  return {
    data: {
      upstream: upstream ?? {
        status: 500,
        code: "upstream_error",
        message: "the request could not be completed",
      },
      requestId: typeof requestId === "string" ? requestId : "",
    },
  };
}

/** The credential the prefetch forwarded, so the hop token can bind to it. */
function rejectedCredential(): string | undefined {
  const jar = cookies();
  return (
    jar.get(env.REDSIM_API_SESSION_COOKIE)?.value ?? jar.get(env.REDSIM_DEV_TOKEN_COOKIE)?.value
  );
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
  const credential = rejectedCredential();
  if (credential === undefined) return "/login";
  const token = await mintHopToken(env.BETTER_AUTH_SECRET ?? "", credential);
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
