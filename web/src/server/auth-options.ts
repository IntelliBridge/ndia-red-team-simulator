// NextAuth options — Keycloak provider + Aegis cookie minting.
//
// Lives in /server/ because the file references the Aegis session
// private key via `mintAegisSessionJwt`. It must never be bundled
// into the client. Next.js 14's App Router only allows specific
// HTTP-verb exports (GET, POST, …) from a route.ts file, so this
// configuration cannot live alongside the route handler — hence the
// dedicated module.

import { cookies } from "next/headers";
import { type NextAuthOptions } from "next-auth";
import KeycloakProvider from "next-auth/providers/keycloak";

import {
  csrfCookieName,
  mintAegisSessionJwt,
  newCsrfToken,
  sessionCookieName,
  sessionTtlSeconds,
} from "./aegis-session";

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
        const maxAge = sessionTtlSeconds;
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
