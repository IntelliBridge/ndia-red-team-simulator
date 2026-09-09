import "server-only";

import type { InputIssues, UpstreamErrorBlock } from "@/lib/trpc/types";

/**
 * `{ fieldErrors, formErrors }` for a schema failure, or undefined.
 *
 * Reads the shape a zod error carries without importing zod or narrowing on
 * `instanceof`, so a schema failure raised by any parser the procedures adopt
 * still resolves to field names a form can render.
 *
 * @param cause - The `cause` of a tRPC `BAD_REQUEST`, usually a `ZodError`.
 * @returns The grouped issues, or undefined when the cause carries none.
 */
export function inputIssues(cause: unknown): InputIssues | undefined {
  const issues = (cause as { issues?: unknown } | null | undefined)?.issues;
  if (!Array.isArray(issues)) return undefined;
  const fieldErrors: Record<string, string[]> = {};
  const formErrors: string[] = [];
  for (const raw of issues) {
    const issue = raw as { path?: unknown; message?: unknown };
    const message = typeof issue.message === "string" ? issue.message : "invalid value";
    const field = Array.isArray(issue.path) ? issue.path.map(String).join(".") : "";
    if (field) (fieldErrors[field] ??= []).push(message);
    else formErrors.push(message);
  }
  return { fieldErrors, formErrors };
}

/**
 * The message a validation refusal shows, in place of the raw cause text.
 *
 * tRPC builds a `BAD_REQUEST` message by stringifying the zod issue array,
 * which is not something to render. The grouped issues travel beside the
 * block, so the block itself carries a sentence and the fields carry the
 * detail.
 */
const VALIDATION_MESSAGE = "the request did not pass validation";

/**
 * The envelope a refusal raised before any upstream call carries.
 *
 * `bad_request` is a web-side code with no row in `redsim/api/errors.py`, the
 * same way `unauthenticated` and `service_unavailable` are: the API never sees
 * one of these, because the input schema refused the call first. A component
 * still has to branch on something, and `upstream_error` with a 500 would say
 * the request failed rather than that a field was wrong.
 *
 * Both paths build the envelope here. The HTTP error formatter and the server
 * prefetch path each call it, which is what keeps the promise that a procedure
 * error reads the same whether it crossed HTTP or was called directly (KTD4,
 * KTD8).
 *
 * @param error - The tRPC error, for its message and its cause.
 * @returns The upstream block, plus the grouped field issues when there are any.
 */
export function badRequestEnvelope(error: { message?: unknown; cause?: unknown }): {
  upstream: UpstreamErrorBlock;
  input?: InputIssues;
} {
  const input = inputIssues(error.cause);
  const message =
    input === undefined && typeof error.message === "string" && error.message
      ? error.message
      : VALIDATION_MESSAGE;
  return {
    upstream: { status: 400, code: "bad_request", message },
    ...(input ? { input } : {}),
  };
}
