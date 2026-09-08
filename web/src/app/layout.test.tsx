// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/components/command-palette", () => ({ CommandPalette: () => null }));
vi.mock("@/components/theme-toggle", () => ({ ThemeToggle: () => null }));
vi.mock("@/components/theme-provider", () => ({
  ThemeProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

import RootLayout, { metadata } from "./layout";

describe("RootLayout", () => {
  it("renders the two nav links and the non-operational footer", () => {
    render(<RootLayout><p>child</p></RootLayout>);
    expect(screen.getByText("Targets", { selector: "a" }).getAttribute("href")).toBe("/targets");
    expect(screen.getByText("Runs", { selector: "a" }).getAttribute("href")).toBe("/runs");
    expect(screen.getByText(/not a safety or readiness determination/i)).toBeTruthy();
  });
  it("has redsim metadata", () => {
    expect(metadata.title).toBe("redsim");
  });
});
