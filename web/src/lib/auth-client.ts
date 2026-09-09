// The Better Auth React client.
//
// Deliberately not under server/: in this tree server/ means "never bundled
// to the browser", and this module is the opposite. It is the browser half.
//
// No baseURL: the handler is served from /api/auth on this same Next server,
// so the client's default of the current origin is correct and avoids baking a
// build-time origin into the bundle.

"use client";

import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient();

export const { signIn, signOut, useSession } = authClient;
