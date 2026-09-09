import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"
import { MriScorecard } from "./mri-scorecard"
import { mri, measurement } from "@/test/fixtures"

describe("MriScorecard", () => {
  it("renders the number and grade when record, measurement, and curve are all present", () => {
    render(<MriScorecard record={mri} measurement={measurement} curvePresent />)
    expect(screen.getByText(String(mri.value))).toBeInTheDocument()
    expect(screen.getByText(mri.grade)).toBeInTheDocument()
    expect(screen.getByText(/not a readiness, safety, or certification statement/i)).toBeInTheDocument()
  })

  it("renders NO number when the curve is absent [spec §15.7]", () => {
    render(<MriScorecard record={mri} measurement={measurement} curvePresent={false} />)
    expect(screen.queryByText(String(mri.value))).not.toBeInTheDocument()
    expect(screen.getByText(/score unavailable/i)).toBeInTheDocument()
  })

  it("renders NO number when measurement is absent", () => {
    render(<MriScorecard record={mri} measurement={null} curvePresent />)
    expect(screen.queryByText(String(mri.value))).not.toBeInTheDocument()
    expect(screen.getByText(/score unavailable/i)).toBeInTheDocument()
  })
})
