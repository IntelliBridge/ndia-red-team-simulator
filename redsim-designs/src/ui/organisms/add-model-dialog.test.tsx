import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, fireEvent } from "@testing-library/react"
import { AddModelDialog } from "./add-model-dialog"

// The dialog reads datasets/capabilities via SWR; stub the fetcher path.
vi.mock("@/lib/hooks", () => ({
  useDatasets: () => ({ data: [{ id: "d1", name: "Open imagery", modality: "image", license: "CC BY 4.0", revision: "r1" }] }),
  useCapabilities: () => ({ data: { phase_b_reasons: { endpoint: "Phase B: remote model endpoints are not yet supported." } } }),
}))
vi.mock("@/lib/session", () => ({ useSession: () => ({ session: { user: "dev", role: "admin", dev: true } }) }))

describe("AddModelDialog", () => {
  beforeEach(() => vi.clearAllMocks())

  it("renders the disabled Phase B endpoint tab reason", () => {
    render(<AddModelDialog onClose={() => {}} onCreated={() => {}} />)
    fireEvent.click(screen.getByRole("button", { name: /Connect endpoint/i }))
    expect(screen.getByText(/remote model endpoints are not yet supported/i)).toBeInTheDocument()
  })

  it("shows the refusal codes on the upload tab [spec §5]", () => {
    render(<AddModelDialog onClose={() => {}} onCreated={() => {}} />)
    fireEvent.click(screen.getByRole("button", { name: /Upload artifact/i }))
    const codes = ["413 model_too_large", "415 unsupported_model_format", "415 pickle_refused", "422 architecture_required"]
    for (const c of codes) expect(screen.getByText(new RegExp(c))).toBeInTheDocument()
  })
})
