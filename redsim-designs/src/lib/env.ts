/**
 * Runtime configuration. All public knobs use the NEXT_PUBLIC_REDSIM_* prefix. [spec §0, D7]
 */
export const REDSIM_ENV = process.env.NEXT_PUBLIC_REDSIM_ENV ?? "dev"
export const IS_PROD = REDSIM_ENV === "prod"

export const API_URL = process.env.NEXT_PUBLIC_REDSIM_API_URL ?? "http://localhost:8000"

/**
 * Named deviation from constitution Principle VI (see alignment report). When on,
 * pages read bundled fixtures instead of the real API and paint a persistent
 * "FIXTURE — illustrative" ribbon. Compiled out of production: even if the env
 * var is set, IS_PROD forces it off. [spec §6, §18.5]
 */
export const DEV_FIXTURES =
  !IS_PROD && process.env.NEXT_PUBLIC_REDSIM_DEV_FIXTURES === "on"

export const BRAND_LONG = "Adversarial ML Red-Team Simulator"
export const BRAND_SHORT = "redsim"

/** Verbatim footer disclosure required on every page. [spec §0, §14.5] */
export const FOOTER_DISCLOSURE =
  "Proof of concept on open, unclassified public data. Results are evidence for human review, not a safety, readiness, or certification determination."
