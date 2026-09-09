import { describe, it, expect, vi } from "vitest"
import { render, screen } from "@testing-library/react"
import { RecommendationCard } from "./recommendation-card"
import type { CandidateRecommendation } from "@/lib/api-types"

vi.mock("@/lib/session", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/session")>()
  return { ...actual, useSession: () => ({ session: { user: "dev", role: "remediator", dev: true } }) }
})
vi.mock("@/lib/hooks", () => ({ useDefenses: () => ({ data: [] }) }))

const base: CandidateRecommendation = {
  id: "rec-1",
  title: "Feature squeezing",
  detail: "Rule output.",
  label: "candidate",
  triggered_by: ["find-1"],
}

describe("RecommendationCard", () => {
  it('shows "not evaluated" until a verify record is present [spec §5]', () => {
    render(<RecommendationCard rec={base} />)
    expect(screen.getByText(/not evaluated/i)).toBeInTheDocument()
    expect(screen.queryByText(/measured ΔMRI/i)).not.toBeInTheDocument()
  })

  it('shows "measured ΔMRI" after verification', () => {
    render(
      <RecommendationCard
        rec={{ ...base, verify: { validation_state: "verified: attack no longer crosses threshold at these settings with feature_squeezing", delta_mri: 12, measured: true } }}
      />,
    )
    expect(screen.getByText(/measured ΔMRI/i)).toBeInTheDocument()
    expect(screen.queryByText(/not evaluated/i)).not.toBeInTheDocument()
  })
})
