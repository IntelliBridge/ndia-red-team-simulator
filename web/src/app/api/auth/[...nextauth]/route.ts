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

import { cookies } from "next/headers";
import NextAuth, { type NextAuthOptions } from "next-auth";
import KeycloakProvider from "next-auth/providers/keycloak";

import {
  csrfCookieName,
  mintAegisSessionJwt,
  newCsrfToken,
  sessionCookieName,
  sessionTtlSeconds,
} from "@/server/aegis-session";

const isProd = (process.env.AEGIS_ENV ?? "dev") === "prod";

export const authOptions: NextAuthOptions = {
  providers: [
    KeycloakProvider({
      clientId: process.env.KEYCLOAK_CLIENT_ID ?? "aegis-web",
      clientSecret: process.env.KEYCLOAK_CLIENT_SECRET ?? "",
      issuer: process.env.KEYCLOAK_ISSUER,
    }),
  ],
  session: { strategy: "jwt" },
  callbacks: {
    async jwt({ token, account, profile }) {
      // Preserve a few claims from Keycloak so the session callback
      // can reuse them without a second token introspection.
      if (account && profile) {
        token.sub = (profile as { sub?: string }).sub ?? token.sub;
        token.email = (profile as { email?: string }).email ?? token.email;
        token.name = (profile as { name?: string }).name ?? token.name;
        const rolesClaim = (profile as Record<string, unknown>)[
          "aegis_project_roles"
        ];
        if (rolesClaim && typeof rolesClaim === "object") {
          token.aegisProjectRoles = rolesClaim as Record<string, string>;
        }
      }
      return token;
    },
    async session({ session, token }) {
      // Mint the Aegis-signed cookies on every session refresh so the
      // SPA can fetch a fresh CSRF token without a full re-login.
      try {
        const jwt = await mintAegisSessionJwt({
          sub: String(token.sub ?? ""),
          email: String(token.email ?? ""),
          name: String(token.name ?? ""),
          projectMemberships:
            (token.aegisProjectRoles as Record<string, string> | undefined) ??
            {},
        });
        const csrf = newCsrfToken();
        const maxAge = sessionTtlSeconds();
        const c = cookies();
        c.set(sessionCookieName, jwt, {
          httpOnly: true,
          secure: isProd,
          sameSite: "lax",
          path: "/",
          maxAge,
        });
        c.set(csrfCookieName, csrf, {
          httpOnly: false,
          secure: isProd,
          sameSite: "lax",
          path: "/",
          maxAge,
        });
      } catch (err) {
        // If mint fails (e.g. AEGIS_API_SESSION_PRIVATE_KEY missing in
        // local dev), keep the NextAuth session intact so the user
        // still sees the UI shell — API calls will surface a 401.
        console.warn("aegis: failed to mint API session cookie", err);
      }
      return session;
    },
  },
  pages: {
    signIn: "/login",
  },
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
