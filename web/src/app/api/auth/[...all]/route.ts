// Better Auth handler for the Keycloak code flow.
//
// Better Auth owns the browser session in its own encrypted cookie. FastAPI
// never sees that cookie; what it sees is the RS256 redsim_api_session cookie
// the after-hook mints through the unchanged mintRedsimSessionJwt, plus the
// non-httpOnly redsim_csrf value the SPA sends back as X-Redsim-CSRF.
//
// The instance and its hook live in @/server/better-auth because Next.js 14's
// App Router only allows HTTP-verb exports from a route.ts file.
//
// The instance is resolved per request rather than at module load. While the
// identity provider is unreachable the route answers 503 with Retry-After and
// caches nothing, so the next request tries again instead of the process
// serving a provider-less Better Auth until it is replaced.

import { toNextJsHandler } from "better-auth/next-js";
import { NextResponse } from "next/server";

import { getAuth, IdentityUnavailableError } from "@/server/better-auth";

type Method = "GET" | "POST";

async function handle(method: Method, req: Request): Promise<Response> {
  let auth: Awaited<ReturnType<typeof getAuth>>;
  try {
    auth = await getAuth();
  } catch (err) {
    if (err instanceof IdentityUnavailableError) {
      console.error("redsim: auth request refused, identity provider unavailable:", err.message);
      return NextResponse.json(
        { error: "identity provider unavailable, retry shortly" },
        { status: 503, headers: { "retry-after": "10" } },
      );
    }
    throw err;
  }
  return toNextJsHandler(auth)[method](req);
}

export const GET = (req: Request) => handle("GET", req);
export const POST = (req: Request) => handle("POST", req);
