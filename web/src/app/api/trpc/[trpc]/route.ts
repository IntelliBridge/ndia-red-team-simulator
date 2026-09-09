// The one HTTP entry point for browser data calls (R1).
//
// force-dynamic because a batched query rides GET and Next 14's route-handler
// cache would otherwise be free to treat it as static, which would both serve
// one user's rows to another and make the request-id header assertion depend
// on Next's default rather than on this file.
import { fetchRequestHandler } from "@trpc/server/adapters/fetch";

import { MAX_BATCH_ITEMS } from "@/lib/trpc/batch";
import { createContext, requestPartsFromRequest } from "@/server/trpc/context";
import { appRouter } from "@/server/trpc/root";

export const dynamic = "force-dynamic";

const ENDPOINT = "/api/trpc";

function handler(request: Request): Promise<Response> {
  const ctx = createContext(requestPartsFromRequest(request));
  return fetchRequestHandler({
    endpoint: ENDPOINT,
    req: request,
    router: appRouter,
    createContext: () => ctx,
    maxBatchSize: MAX_BATCH_ITEMS,
    responseMeta: () => ({
      headers: {
        // Comma-joined in call order, so a user can quote the id of any call
        // in the batch (R3).
        "X-Redsim-Request-ID": ctx.requestIds.join(","),
        "Cache-Control": "no-store",
      },
    }),
  });
}

export { handler as GET, handler as POST };
