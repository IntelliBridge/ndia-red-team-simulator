// Client-safe tRPC types.
//
// Everything here is erased at build time. The router import is a top-level
// `import type`, which verbatimModuleSyntax erases entirely; an inline type
// specifier would leave the side-effect import behind and pull the server
// router into the browser bundle, where the `server-only` guard turns it into
// a build error (KTD2).
import type { inferRouterInputs, inferRouterOutputs } from "@trpc/server";

import type { AppRouter } from "@/server/trpc/root";

export type RouterInputs = inferRouterInputs<AppRouter>;
export type RouterOutputs = inferRouterOutputs<AppRouter>;

/**
 * The spec 17.3 envelope as it reaches a component.
 *
 * An object `detail` is carried whole, so every extra field the envelope
 * names (`phase`, `field`, `reasons`, `allowed`, `refusal_reason`, `run_id`,
 * `target_id`) survives. A plain-string `detail` from a retained route arrives
 * as `message` with a code synthesized from the HTTP status (KTD8, R4).
 *
 * `status` here is always the HTTP status. The API's own envelope uses that
 * name for a domain value too, so an envelope that carries one arrives as
 * `detail_status`: a 409 `run_terminal` from `POST /v1/runs/{id}/cancel` has
 * `status: 409` and `detail_status: "succeeded"`.
 */
export type UpstreamErrorBlock = {
  status: number;
  code: string;
  message: string;
  [extra: string]: unknown;
};

/**
 * A schema failure, grouped the way a form renders it.
 *
 * `fieldErrors` is keyed by the dotted input path, so a leaf can put a message
 * next to the control that caused it. `formErrors` holds the issues with no
 * path of their own.
 */
export type InputIssues = {
  fieldErrors: Record<string, string[]>;
  formErrors: string[];
};

/** What a procedure attaches to every error it throws (R3, R4). */
export type UpstreamErrorData = {
  upstream: UpstreamErrorBlock;
  requestId: string;
  /**
   * Present only when the input schema refused the call.
   *
   * A sibling of `upstream` rather than a field inside it, because the block
   * mirrors the API's own envelope and the API never saw this request.
   */
  input?: InputIssues;
};
