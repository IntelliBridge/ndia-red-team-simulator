import {
  MutationCache,
  QueryCache,
  QueryClient,
  defaultShouldDehydrateQuery,
} from "@tanstack/react-query";

import { upstreamError } from "@/lib/api";

/** How long a hydrated query counts as fresh (KTD4). */
export const DEFAULT_STALE_TIME_MS = 30_000;

export type QueryClientOptions = {
  /**
   * Called for any query or mutation whose error is an API 401.
   *
   * Receives the client it belongs to, so the caller can clear the cache
   * without closing over a binding that does not exist yet. The client
   * provider posts the sign-out route and navigates to /login from here. The
   * server leaves it unset: a server component cannot write cookies, so the
   * prefetch helper redirects through the sign-out hop instead (KTD7).
   */
  onUnauthorized?: (client: QueryClient) => void;
};

function isUnauthorized(error: unknown): boolean {
  return upstreamError(error)?.status === 401;
}

/**
 * The QueryClient both sides share.
 *
 * `staleTime` stops the client refetching a hydrated query that has data.
 * `retryOnMount: false` is what stops a hydrated *error* refetching: TanStack
 * remounts an errored query with no data unless the flag is off, so without it
 * a server-rendered error state would flip to pending the moment the leaf
 * mounted. It governs mount only, so the poll intervals of R10 still recover
 * an errored key at their next tick, and ErrorState's retry still refetches on
 * demand.
 *
 * Errored queries are dehydrated alongside successful ones, so a leaf whose
 * key failed on the server mounts with the typed error already in cache and
 * renders its honest state in the server HTML (KTD4, R9).
 */
export function makeQueryClient(options: QueryClientOptions = {}): QueryClient {
  const onError = (error: unknown) => {
    if (isUnauthorized(error)) options.onUnauthorized?.(client);
  };
  const client = new QueryClient({
    queryCache: new QueryCache({ onError }),
    mutationCache: new MutationCache({ onError }),
    defaultOptions: {
      queries: {
        staleTime: DEFAULT_STALE_TIME_MS,
        retryOnMount: false,
        retry: false,
      },
      dehydrate: {
        shouldDehydrateQuery: (query) =>
          defaultShouldDehydrateQuery(query) || query.state.status === "error",
      },
    },
  });
  return client;
}
