// Server-side entry points for the Better Auth instance.
//
// Separate from config.ts so that constructing an instance (which runs OIDC
// discovery) is distinguishable from reading the current session.
//
// The instance is built lazily and only after the issuer's discovery document
// answers. Better Auth's generic-oauth plugin runs discovery once, at the
// first request, and a failure drops the Keycloak provider for the life of the
// process with nothing but a log line. On the Fargate runtime the web and
// identity services roll concurrently and identity is a stop-then-start
// deployment, so a web task whose first auth request lands inside that window
// used to serve "Provider not found" until someone replaced it. Probing first
// and caching nothing on failure turns that into a 503 that heals itself on
// the next request.

import { headers } from "next/headers";

import { env } from "@/env";

import { createAuth } from "./config";

type Auth = ReturnType<typeof createAuth>;

/** The identity provider could not be reached; the caller should retry. */
export class IdentityUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IdentityUnavailableError";
  }
}

const DISCOVERY_TIMEOUT_MS = 5_000;

let instance: Auth | null = null;
let building: Promise<Auth> | null = null;

async function probeDiscovery(issuer: string): Promise<void> {
  const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  let res: Response;
  try {
    res = await fetch(url, { signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS) });
  } catch (err) {
    throw new IdentityUnavailableError(
      `discovery fetch failed for ${url}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!res.ok) {
    throw new IdentityUnavailableError(`discovery at ${url} returned ${res.status}`);
  }
}

/**
 * The process-wide instance, built on first use.
 *
 * Rejects with IdentityUnavailableError, and caches nothing, while Keycloak's
 * discovery document is unreachable. Concurrent callers share one build.
 */
export async function getAuth(): Promise<Auth> {
  if (instance) return instance;
  building ??= (async () => {
    try {
      if (env.KEYCLOAK_ISSUER && env.KEYCLOAK_CLIENT_ID) {
        await probeDiscovery(env.KEYCLOAK_ISSUER);
      }
      instance = createAuth();
      return instance;
    } finally {
      building = null;
    }
  })();
  return building;
}

/**
 * The caller's Better Auth session, or null.
 *
 * Reads the request headers rather than taking them as an argument, so route
 * handlers call it with no plumbing. An unreachable identity provider reads
 * as no session: the caller answers 401 and the browser goes back through
 * login, which is where the 503 surfaces.
 */
export async function getSession() {
  let auth: Auth;
  try {
    auth = await getAuth();
  } catch (err) {
    if (err instanceof IdentityUnavailableError) {
      console.error("redsim: identity provider unavailable, treating as signed out:", err.message);
      return null;
    }
    throw err;
  }
  return auth.api.getSession({ headers: headers() });
}
