// NextAuth handler — Keycloak code flow.
//
// Phase 4 v0.4.0 F13. NextAuth manages the browser session; the
// JWT callback runs server-side after Keycloak returns. In `session`
// we mint:
//   - `aegis_api_session` (httpOnly, secure-in-prod, sameSite=Lax)
//     signed with AEGIS_API_SESSION_PRIVATE_KEY → FastAPI verifies
//     against the matching public key.
//   - `aegis_csrf` (NOT httpOnly so JS can read it) used by the
//     SPA's api() helper as the X-Aegis-CSRF header on every
//     POST/PUT/PATCH/DELETE.
//
// FastAPI never sees NextAuth's session JWT — it's signed with
// NEXTAUTH_SECRET, which is a Node-only secret.
//
// The NextAuthOptions config + cookie-minting callback live in
// @/server/auth-options because Next.js 14's App Router only allows
// HTTP-verb exports (GET, POST, …) from a route.ts file. Importing
// from a sibling /server module is the standard escape hatch.

import NextAuth from "next-auth";

import { authOptions } from "@/server/auth-options";

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
