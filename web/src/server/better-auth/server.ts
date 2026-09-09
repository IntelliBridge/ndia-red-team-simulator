// Server-side entry points for the Better Auth instance.
//
// Separate from config.ts so that constructing an instance (which runs OIDC
// discovery) is distinguishable from reading the current session.

import { headers } from "next/headers";

import { createAuth } from "./config";

/** The process-wide instance. Discovery runs once, at first import. */
export const auth = createAuth();

/**
 * The caller's Better Auth session, or null.
 *
 * Reads the request headers rather than taking them as an argument, so route
 * handlers call it with no plumbing.
 */
export async function getSession() {
  return auth.api.getSession({ headers: headers() });
}
