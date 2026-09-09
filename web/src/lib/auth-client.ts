// The Better Auth React client.
//
// Deliberately not under server/: in this tree server/ means "never bundled
// to the browser", and this module is the opposite. It is the browser half.
//
// Sign-in no longer goes through here: the branded login page posts to
// /api/auth/login, which runs the Keycloak password grant server-side. What
// remains is sign-out, which still ends a Better Auth session and the
// Keycloak SSO session behind it for a browser that signed in through the
// code flow before the branded page landed.
//
// No baseURL: the handler is served from /api/auth on this same Next server,
// so the client's default of the current origin is correct and avoids baking a
// build-time origin into the bundle.

"use client";

import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient();

export const { signOut, useSession } = authClient;
