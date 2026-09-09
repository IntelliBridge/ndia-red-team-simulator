// Better Auth handler for the Keycloak code flow.
//
// Better Auth owns the browser session in its own encrypted cookie. FastAPI
// never sees that cookie; what it sees is the RS256 redsim_api_session cookie
// the after-hook mints through the unchanged mintRedsimSessionJwt, plus the
// non-httpOnly redsim_csrf value the SPA sends back as X-Redsim-CSRF.
//
// The instance and its hook live in @/server/better-auth because Next.js 14's
// App Router only allows HTTP-verb exports from a route.ts file.

import { toNextJsHandler } from "better-auth/next-js";

import { auth } from "@/server/better-auth";

export const { GET, POST } = toNextJsHandler(auth);
