"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { QueryClientProvider, type QueryClient } from "@tanstack/react-query";
import { createTRPCClient, httpBatchLink } from "@trpc/client";
import { createTRPCContext } from "@trpc/tanstack-react-query";

import { env } from "@/env";
import { readCookie } from "@/lib/api";
import { MAX_BATCH_ITEMS } from "@/lib/trpc/batch";
import { makeQueryClient } from "@/lib/trpc/query-client";
// A top-level type import, erased by verbatimModuleSyntax. An inline type
// specifier here would leave the side-effect import in the browser bundle and
// the `server-only` guard would fail the build (KTD2).
import type { AppRouter } from "@/server/trpc/root";

export const { TRPCProvider, useTRPC, useTRPCClient } = createTRPCContext<AppRouter>();

let browserQueryClient: QueryClient | undefined;

/**
 * One QueryClient for the browser, a fresh one per render on the server.
 *
 * Reusing the browser instance is what lets a hydrated key stay hydrated
 * across a client-side navigation.
 */
function getQueryClient(onUnauthorized: (client: QueryClient) => void): QueryClient {
  if (typeof window === "undefined") return makeQueryClient();
  browserQueryClient ??= makeQueryClient({ onUnauthorized });
  return browserQueryClient;
}

/**
 * Whether a sign-out is already in flight.
 *
 * The QueryClient's onError fires once per errored query, and one batch can
 * carry up to MAX_BATCH_ITEMS calls that all answer 401 together. Without this
 * flag a full batch fired that many sign-out posts, cache clears and
 * navigations. Module level rather than a ref, because every provider instance
 * shares the one browser QueryClient below.
 */
let signingOut = false;

export function TRPCReactProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();

  const [queryClient] = useState(() =>
    getQueryClient((client) => {
      if (signingOut) return;
      signingOut = true;
      // A rejected cookie has to be cleared before /login renders: the
      // middleware gate checks presence alone and would bounce straight back
      // to /dashboard otherwise (KTD7).
      void fetch("/api/auth/signout-redsim", { method: "POST" })
        // Best effort. Offline the post never lands, and the local clear and
        // the redirect still have to happen. The catch is also what keeps that
        // case quiet: `finally` re-propagates the original rejection, so
        // without it an offline sign-out surfaced as an unhandled rejection.
        .catch(() => undefined)
        .finally(() => {
          // Including hydrated data, so a second user in the same tab never
          // sees the previous user's rows out of the 30 s stale window.
          client.clear();
          router.replace("/login");
          signingOut = false;
        });
    }),
  );

  const [trpcClient] = useState(() =>
    createTRPCClient<AppRouter>({
      links: [
        httpBatchLink({
          url: "/api/trpc",
          maxItems: MAX_BATCH_ITEMS,
          headers() {
            // Double-submit stays end to end: the browser reads the
            // non-httpOnly csrf cookie and the procedure forwards the header
            // verbatim. The server never synthesizes it from the cookie,
            // because that would make the cookie jar alone proof of intent
            // (KTD2, R35).
            const csrf = readCookie(env.NEXT_PUBLIC_REDSIM_CSRF_COOKIE);
            return csrf ? { [env.NEXT_PUBLIC_REDSIM_CSRF_HEADER]: csrf } : {};
          },
        }),
      ],
    }),
  );

  return (
    <QueryClientProvider client={queryClient}>
      <TRPCProvider trpcClient={trpcClient} queryClient={queryClient}>
        {children}
      </TRPCProvider>
    </QueryClientProvider>
  );
}
