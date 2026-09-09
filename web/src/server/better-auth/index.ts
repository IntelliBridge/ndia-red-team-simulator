// Barrel for the Better Auth server modules. Import from here, never from the
// internals, so the "never bundled to the browser" boundary stays one line to
// check.

export { createAuth } from "./config";
export { getAuth, getSession, IdentityUnavailableError } from "./server";
