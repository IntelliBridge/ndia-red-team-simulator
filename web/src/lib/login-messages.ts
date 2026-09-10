// The sentences the login page shows. One place, so the route answers a code
// and the page never guesses at wording. Nothing here names the identity
// provider: the user signs in to redsim.

/** The codes the login route answers with, plus the two the client adds. */
export type LoginFailure =
  | "invalid_request"
  | "invalid_credentials"
  | "account_disabled"
  | "account_locked"
  | "not_configured"
  | "unavailable"
  | "unknown";

const MESSAGES: Record<LoginFailure, string> = {
  invalid_request: "Enter your email and password.",
  invalid_credentials: "That email and password did not match. Check both and try again.",
  account_disabled: "This account cannot sign in right now. Contact your administrator.",
  account_locked:
    "Too many attempts. This account is locked for a short while. Wait a few minutes and try again.",
  not_configured: "Sign-in is not available right now. Contact your administrator.",
  unavailable: "Sign-in is not available right now. Try again in a moment.",
  unknown: "Something went wrong while signing in. Try again.",
};

export function loginMessage(code: string): string {
  return MESSAGES[(code in MESSAGES ? code : "unknown") as LoginFailure];
}

/** Why the browser landed on /login, from the `reason` query parameter. */
const REASONS: Record<string, string> = {
  rejected: "Your session ended. Sign in again to continue.",
  signed_out: "You are signed out.",
};

export function reasonMessage(reason: string | null | undefined): string | undefined {
  return reason ? REASONS[reason] : undefined;
}

/**
 * Where to go after a successful sign-in.
 *
 * Only a same-origin path is honoured: it must start with one slash and not
 * two, and it may not be the login page itself. Anything else, including an
 * absolute URL, falls back to the dashboard so the parameter cannot bounce a
 * user to another site.
 */
export function safeNextPath(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) {
    return "/dashboard";
  }
  if (next === "/login" || next.startsWith("/login?") || next === "/") return "/dashboard";
  return next;
}
