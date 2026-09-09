/**
 * Validated environment for the web process.
 *
 * Every `process.env` read under `web/src` goes through this module, with two
 * deliberate exceptions. `web/src/server/redsim-session.ts` reads the signing
 * key and cookie names directly, because the FastAPI session-cookie contract
 * freezes that file byte for byte. And `web/src/server/trpc/context.ts` reads
 * `process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES` as a literal member expression
 * to gate the dynamic import of the fixture module, because Next only inlines
 * the literal read and a property lookup on the object below is not a constant
 * the bundler can fold away. A build without the flag therefore drops the
 * module from the output; this schema still validates the same name for the
 * ribbon and for the refinement at the bottom of the file.
 *
 * Centralizing the reads buys two things a scattered `process.env.X ?? default`
 * does not. A missing or malformed value fails at boot naming the variable,
 * rather than surfacing later as a 401 or a request to the wrong origin. And
 * the defaults live in one schema, so the value a page sees and the value the
 * deploy surfaces document are the same value.
 *
 * `SKIP_ENV_VALIDATION=1` relaxes the two required server names for a build
 * that has no runtime environment yet. It belongs in a Docker build stage and
 * in CI, and nowhere else.
 */
import { createEnv } from "@t3-oss/env-nextjs";
import { z } from "zod";

/**
 * The environments that may honour a dev token or answer from fixtures.
 *
 * `REDSIM_ENV` defaults to `dev` below, so an unset value reads as `dev` and
 * every deployment that omits the variable keeps booting the way it does
 * today. Anything outside this list -- `prod`, `staging`, a typo -- refuses
 * both, in middleware and in the tRPC context alike (KTD7, KTD13).
 */
export const DEV_ENVS = ["dev", "test"];

/**
 * An operator writes `REDSIM_DEV_FIXTURES=1`, not `=true`, so accept the
 * spellings a compose file or a task definition actually carries and treat
 * everything else as off.
 *
 * @param {string} [fallback]
 */
const flag = (fallback = "0") =>
  z
    .string()
    .default(fallback)
    .transform((v) => ["1", "true", "on", "yes"].includes(v.trim().toLowerCase()));

/**
 * The build-time escape hatch, narrowed to the server names that a build
 * genuinely cannot supply.
 *
 * `createEnv`'s `skipValidation` switches off the whole schema and returns
 * the raw environment. That is wrong here, and measurably so: Next inlines
 * every `NEXT_PUBLIC_*` read at build time, so a build with the whole schema
 * off bakes `undefined` in place of each client default and ships an image
 * whose API base is the string "undefined". It also fails the build
 * outright, because `apiWsBase` derives from that value at module scope and
 * every prerendered page evaluates it.
 */
const buildTime = !!process.env.SKIP_ENV_VALIDATION;

/**
 * Required when the process is actually running, optional during a build.
 *
 * @template {import("zod").ZodTypeAny} T
 * @param {T} schema
 */
const requiredAtRuntime = (schema) => (buildTime ? schema.optional() : schema);

export const env = createEnv({
  /**
   * Server-only variables. Never inlined into the browser bundle, and never
   * readable from a client component.
   */
  server: {
    // Better Auth refuses to start without these two, and rotating the secret
    // invalidates every live browser session.
    BETTER_AUTH_SECRET: requiredAtRuntime(
      z.string().min(32, "BETTER_AUTH_SECRET must be at least 32 characters"),
    ),
    BETTER_AUTH_URL: requiredAtRuntime(z.string().url()),
    // Drives the Secure attribute on both redsim cookies.
    REDSIM_ENV: z.string().default("dev"),
    // Optional so a developer can boot the app without a realm. Better Auth
    // discovers the issuer at construction and skips the provider when it is
    // absent, which is the documented local-dev shape.
    KEYCLOAK_ISSUER: z.string().url().optional(),
    KEYCLOAK_CLIENT_ID: z.string().optional(),
    // The realm's redsim-web is a public client using PKCE, so this stays
    // unset in every environment the repo ships.
    KEYCLOAK_CLIENT_SECRET: z.string().optional(),
    // Read here so `.env.example` and the deploy surfaces can document them.
    // redsim-session.ts still reads them from process.env directly.
    REDSIM_API_SESSION_PRIVATE_KEY: z.string().optional(),
    REDSIM_API_SESSION_KEY_ID: z.string().optional(),
    REDSIM_API_SESSION_TTL_SECONDS: z.string().optional(),
    // Defaulted rather than optional so the edge-bundled middleware gate and
    // the tRPC context read the three cookie names from one validated source.
    // redsim-session.ts keeps its own `?? "redsim_api_session"` fallback and
    // stays byte-identical to the base (R14).
    REDSIM_API_SESSION_COOKIE: z.string().default("redsim_api_session"),
    REDSIM_CSRF_COOKIE: z.string().default("redsim_csrf"),
    REDSIM_DEV_TOKEN_COOKIE: z.string().default("redsim_dev_token"),
    // The tRPC layer's upstream base. Server-only, so changing where FastAPI
    // lives no longer rebuilds the web image (KTD6).
    REDSIM_API_URL: z.string().url().default("http://localhost:8000"),
    // The runtime authority for answering from fixtures. A public build-time
    // flag cannot be the authority, because the web image builds with
    // SKIP_ENV_VALIDATION and no REDSIM_ENV (KTD13).
    REDSIM_DEV_FIXTURES: flag(),
  },

  /**
   * Browser-visible variables. Each default is the literal the call site used
   * before this module existed, so behavior is unchanged.
   */
  client: {
    NEXT_PUBLIC_REDSIM_API_URL: z.string().url().default("http://localhost:8000"),
    NEXT_PUBLIC_REDSIM_ENV: z.string().default("dev"),
    // No client name for the session cookie: it is httpOnly, so JavaScript
    // cannot read it, and the server has REDSIM_API_SESSION_COOKIE (KTD6).
    NEXT_PUBLIC_REDSIM_CSRF_COOKIE: z.string().default("redsim_csrf"),
    NEXT_PUBLIC_REDSIM_CSRF_HEADER: z.string().default("X-Redsim-CSRF"),
    // Paints the fixture ribbon, and its inlined value is the branch behind
    // the dynamic import of the fixture module (KTD13).
    NEXT_PUBLIC_REDSIM_DEV_FIXTURES: flag(),
  },

  /**
   * Next.js inlines `process.env.NEXT_PUBLIC_*` only where it appears as a
   * literal member expression, so every name is destructured explicitly here
   * rather than spread from `process.env`.
   */
  runtimeEnv: {
    BETTER_AUTH_SECRET: process.env.BETTER_AUTH_SECRET,
    BETTER_AUTH_URL: process.env.BETTER_AUTH_URL,
    REDSIM_ENV: process.env.REDSIM_ENV,
    KEYCLOAK_ISSUER: process.env.KEYCLOAK_ISSUER,
    KEYCLOAK_CLIENT_ID: process.env.KEYCLOAK_CLIENT_ID,
    KEYCLOAK_CLIENT_SECRET: process.env.KEYCLOAK_CLIENT_SECRET,
    REDSIM_API_SESSION_PRIVATE_KEY: process.env.REDSIM_API_SESSION_PRIVATE_KEY,
    REDSIM_API_SESSION_KEY_ID: process.env.REDSIM_API_SESSION_KEY_ID,
    REDSIM_API_SESSION_TTL_SECONDS: process.env.REDSIM_API_SESSION_TTL_SECONDS,
    REDSIM_API_SESSION_COOKIE: process.env.REDSIM_API_SESSION_COOKIE,
    REDSIM_CSRF_COOKIE: process.env.REDSIM_CSRF_COOKIE,
    REDSIM_DEV_TOKEN_COOKIE: process.env.REDSIM_DEV_TOKEN_COOKIE,
    REDSIM_API_URL: process.env.REDSIM_API_URL,
    REDSIM_DEV_FIXTURES: process.env.REDSIM_DEV_FIXTURES,
    NEXT_PUBLIC_REDSIM_API_URL: process.env.NEXT_PUBLIC_REDSIM_API_URL,
    NEXT_PUBLIC_REDSIM_ENV: process.env.NEXT_PUBLIC_REDSIM_ENV,
    NEXT_PUBLIC_REDSIM_CSRF_COOKIE: process.env.NEXT_PUBLIC_REDSIM_CSRF_COOKIE,
    NEXT_PUBLIC_REDSIM_CSRF_HEADER: process.env.NEXT_PUBLIC_REDSIM_CSRF_HEADER,
    NEXT_PUBLIC_REDSIM_DEV_FIXTURES:
      process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES,
  },

  /**
   * Fixture mode cannot exist outside a dev or test environment (KTD13).
   *
   * The refinement runs on the combined shape rather than on either flag
   * alone, because the pair is what is illegal: `REDSIM_DEV_FIXTURES` is the
   * runtime authority and `NEXT_PUBLIC_REDSIM_DEV_FIXTURES` is what a build
   * inlines, and either one on in `prod` or `staging` is a misconfiguration
   * that must fail at boot and at build rather than serve fake evidence.
   *
   * It is applied only when the server shape is present. On the browser the
   * server names are not part of the parsed object at all, so there is no
   * `REDSIM_ENV` to check; the same build already failed on the server side
   * if the combination was illegal.
   */
  createFinalSchema: (shape, isServer) =>
    z.object(shape).superRefine((value, ctx) => {
      if (!isServer) return;
      const parsed = /** @type {Record<string, unknown>} */ (value);
      const redsimEnv = /** @type {string | undefined} */ (parsed.REDSIM_ENV);
      if (redsimEnv === undefined || DEV_ENVS.includes(redsimEnv)) return;
      for (const name of ["REDSIM_DEV_FIXTURES", "NEXT_PUBLIC_REDSIM_DEV_FIXTURES"]) {
        if (parsed[name] !== true) continue;
        ctx.addIssue({
          code: "custom",
          path: [name],
          message: `fixture mode is refused when REDSIM_ENV is "${redsimEnv}" (allowed: ${DEV_ENVS.join(", ")})`,
        });
      }
    }),

  /**
   * An operator who writes `KEYCLOAK_ISSUER=` in a compose file means "unset",
   * not "the empty string".
   */
  emptyStringAsUndefined: true,

  /**
   * The default handler throws "Invalid environment variables" and logs the
   * names separately, which is unreadable in a container that exits at
   * startup. Put the names in the thrown message instead.
   */
  onValidationError: (issues) => {
    const named = issues
      .map((issue) => `${issue.path?.join(".") ?? "(root)"}: ${issue.message}`)
      .join("; ");
    throw new Error(`Invalid environment variables: ${named}`);
  },
});
