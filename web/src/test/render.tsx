// Rendering a client leaf the way the app renders it.
//
// A fresh QueryClient per case (so nothing leaks between tests), the real
// TRPCProvider, and a tRPC client whose link is fed by a mock rather than the
// network. `dehydratedState` is what makes the hydration assertions possible:
// pass the state a server prefetch would have produced and the leaf mounts
// with data, or with its typed error, already in cache.

import type { ReactElement, ReactNode } from "react";
import {
  HydrationBoundary,
  QueryClientProvider,
  type DehydratedState,
  type QueryClient,
} from "@tanstack/react-query";
import { createTRPCClient, httpBatchLink } from "@trpc/client";
import { render, type RenderResult } from "@testing-library/react";
import { vi } from "vitest";

import { MAX_BATCH_ITEMS } from "@/lib/trpc/batch";
import { TRPCProvider } from "@/lib/trpc/client";
import { makeQueryClient } from "@/lib/trpc/query-client";
// Type-only, so nothing under src/server/ is loaded into the jsdom bundle.
import type { AppRouter } from "@/server/trpc/root";

export type TrpcFetchMock = ReturnType<typeof vi.fn>;

export type RenderWithProvidersOptions = {
  /** What a server prefetch would have handed the leaf. */
  dehydratedState?: DehydratedState;
  /**
   * Answers for calls the leaf makes itself: one entry per call in the batch,
   * in call order. Every batched request gets the same array.
   */
  respond?: () => unknown[];
  queryClient?: QueryClient;
};

export type RenderWithProvidersResult = RenderResult & {
  queryClient: QueryClient;
  /** Every request the link issued. Length is the assertion for "no refetch". */
  trpcFetch: TrpcFetchMock;
};

export function renderWithProviders(ui: ReactElement, options: RenderWithProvidersOptions = {}) {
  const queryClient = options.queryClient ?? makeQueryClient();

  const trpcFetch = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) =>
    Promise.resolve(
      new Response(JSON.stringify(options.respond?.() ?? [{ result: { data: null } }]), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    ),
  );

  const trpcClient = createTRPCClient<AppRouter>({
    links: [
      httpBatchLink({
        url: "http://localhost:3000/api/trpc",
        maxItems: MAX_BATCH_ITEMS,
        fetch: trpcFetch as unknown as typeof fetch,
      }),
    ],
  });

  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <TRPCProvider trpcClient={trpcClient} queryClient={queryClient}>
          <HydrationBoundary state={options.dehydratedState}>{children}</HydrationBoundary>
        </TRPCProvider>
      </QueryClientProvider>
    );
  }

  // Object.assign rather than a spread: spreading the render result drops the
  // query helpers from its type.
  return Object.assign(render(ui, { wrapper: Wrapper }), { queryClient, trpcFetch });
}
