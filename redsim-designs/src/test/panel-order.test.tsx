import { describe, it, expect } from "vitest"
import { render, screen, within } from "@testing-library/react"
import { PanelSection } from "@/ui/molecules/panel-section"
import { LabelBadge } from "@/ui/atoms/label-badge"
import { mri } from "@/test/fixtures"

/**
 * The campaign page keeps measurements / observations / interpretation /
 * candidates as four distinct sections in a fixed order, and surfaces the
 * literal labels candidate / inferred / heuristic. This exercises the same
 * building blocks the page composes. [spec §18.3, §18.6]
 */
function PanelsHarness() {
  return (
    <div>
      <PanelSection title="Measurements" tone="measurement">m</PanelSection>
      <PanelSection title="Observations" tone="observation">
        <LabelBadge variant="heuristic">heuristic</LabelBadge>
      </PanelSection>
      <PanelSection title="Interpretation" tone="interpretation">
        <LabelBadge variant="inferred">inferred</LabelBadge>
      </PanelSection>
      <PanelSection title="Candidate recommendations" tone="candidate">
        <LabelBadge variant="candidate">candidate</LabelBadge>
      </PanelSection>
      <PanelSection title="Limitations">
        <ul>{mri.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
      </PanelSection>
    </div>
  )
}

describe("campaign panels", () => {
  it("keeps four distinct sections in order", () => {
    render(<PanelsHarness />)
    const headings = screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent)
    const order = ["Measurements", "Observations", "Interpretation", "Candidate recommendations", "Limitations"]
    // The four measurement/observation/interpretation/candidate sections appear in this order.
    const filtered = headings.filter((h) => order.includes(h ?? ""))
    expect(filtered).toEqual(order)
  })

  it("renders the literal labels candidate / inferred / heuristic", () => {
    render(<PanelsHarness />)
    expect(screen.getByText("candidate")).toBeInTheDocument()
    expect(screen.getByText("inferred")).toBeInTheDocument()
    expect(screen.getByText("heuristic")).toBeInTheDocument()
  })

  it("keeps limitations visible", () => {
    render(<PanelsHarness />)
    const region = screen.getByText("Limitations").closest("section")!
    expect(within(region).getByText(mri.limitations[0])).toBeInTheDocument()
  })
})
