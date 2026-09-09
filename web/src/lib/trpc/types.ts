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
 * names (`phase`, `field`, `reasons`, `allowed`, `status`, `refusal_reason`,
 * `run_id`, `target_id`) survives. A plain-string `detail` from a retained
 * route arrives as `message` with a code synthesized from the HTTP status
 * (KTD8, R4).
 */
export type UpstreamErrorBlock = {
  status: number;
  code: string;
  message: string;
  [extra: string]: unknown;
};

/** What a procedure attaches to every error it throws (R3, R4). */
export type UpstreamErrorData = {
  upstream: UpstreamErrorBlock;
  requestId: string;
};
