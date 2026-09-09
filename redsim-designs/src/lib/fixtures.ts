/**
 * Dev-only fixture router. Active only when NEXT_PUBLIC_REDSIM_DEV_FIXTURES=on
 * and not in prod. Maps API paths to the illustrative records under test/.
 * Every page paints the FIXTURE ribbon while this is live. [spec §6]
 */
import * as fx from "@/test/fixtures"
import { ApiError } from "./api"

function match(path: string, pattern: RegExp) {
  return pattern.exec(path)
}

export async function fixtureFetch<T>(path: string, method: string, _body?: unknown): Promise<T> {
  // Simulate a little latency so loading states are visible.
  await new Promise((r) => setTimeout(r, 120))

  const p = path.split("?")[0]

  // Mutations echo a run id / ok.
  if (method !== "GET") {
    if (/\/attacks$/.test(p)) return { run_id: fx.campaign.run_id } as T
    if (/\/verify$/.test(p)) return { run_id: "run-verify-1" } as T
    return { ok: true } as T
  }

  if (p === "/v1/ml/capabilities") return fx.capabilities as T
  if (p === "/v1/attacks") return fx.attacks as T
  if (p === "/v1/defenses") return fx.defenses as T
  if (p === "/v1/datasets") return fx.datasets as T
  if (p === "/v1/models") return fx.models as T
  if (p === "/v1/projects") return fx.projects as T
  if (p === "/v1/auth-profiles") return fx.authProfiles as T
  if (p === "/v1/logs") return fx.logs as T
  if (/^\/v1\/orgs\/[^/]+\/cost$/.test(p)) return fx.cost as T
  if (p === "/v1/audit/verify") return fx.audit as T
  if (p === "/v1/runs") return fx.runsList as T
  if (p === "/v1/findings") return fx.findings as T

  let m
  if ((m = match(p, /^\/v1\/models\/([^/]+)$/))) {
    const model = fx.models.find((x) => x.id === m![1])
    if (!model) throw new ApiError(404, { code: "not_found", message: "Model not found" })
    return model as T
  }
  if ((m = match(p, /^\/v1\/runs\/([^/]+)\/campaign$/))) return fx.campaign as T
  if ((m = match(p, /^\/v1\/runs\/([^/]+)\/measurement$/))) return fx.measurement as T
  if ((m = match(p, /^\/v1\/runs\/([^/]+)\/mri$/))) return fx.mri as T
  if ((m = match(p, /^\/v1\/runs\/([^/]+)\/observations$/))) return fx.observations as T
  if ((m = match(p, /^\/v1\/runs\/([^/]+)\/interpretation$/))) return fx.interpretations as T
  if ((m = match(p, /^\/v1\/runs\/([^/]+)\/recommendations$/))) return fx.recommendations as T
  if ((m = match(p, /^\/v1\/runs\/([^/]+)\/provenance$/))) return fx.provenance as T
  if ((m = match(p, /^\/v1\/runs\/([^/]+)\/artifacts$/))) return [] as T
  if ((m = match(p, /^\/v1\/runs\/([^/]+)\/compare$/))) return fx.comparison as T
  if ((m = match(p, /^\/v1\/runs\/([^/]+)$/))) return fx.campaign as T
  if ((m = match(p, /^\/v1\/findings\/([^/]+)$/))) {
    const f = fx.findings.find((x) => x.id === m![1]) ?? fx.findings[0]
    return f as T
  }

  throw new ApiError(404, { code: "not_found", message: `No fixture for ${p}` })
}
