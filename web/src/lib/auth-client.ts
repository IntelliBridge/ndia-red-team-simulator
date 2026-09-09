// The Better Auth React client.
//
// Deliberately not under server/. T3 puts createAuthClient at
// src/server/better-auth/client.ts, but in this tree server/ means "never
// bundled to the browser" (R12), and this module is the opposite: it is the
// browser half.
//
// No baseURL: the handler is served from /api/auth on this same Next server,
// so the client's default of the current origin is correct and avoids baking a
// build-time origin into the bundle.

"use client";

import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient();

export const { signIn, signOut, useSession } = authClient;
