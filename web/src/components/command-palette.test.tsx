import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Router push is asserted when an item is selected.
const pushMock = vi.hoisted(() => vi.fn());
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
  usePathname: () => "/runs",
}));

// Mock the design-system Command primitives to deterministic passthroughs so
// the test exercises this component's chord + navigation logic rather than
// Radix dialog/cmdk portal internals. CommandDialog only renders children
// when `open`, mirroring the real dialog's mounted-when-open behaviour.
vi.mock("@redsim/design-system", () => ({
  CommandDialog: ({
    open,
    children,
  }: {
    open: boolean;
    onOpenChange: (o: boolean) => void;
    children: React.ReactNode;
  }) =>
    open
      ? React.createElement("div", { "data-testid": "palette" }, children)
      : null,
  CommandInput: (props: Record<string, unknown>) =>
    React.createElement("input", props as object),
  CommandList: ({ children }: { children: React.ReactNode }) =>
    React.createElement("div", null, children),
  CommandEmpty: ({ children }: { children: React.ReactNode }) =>
    React.createElement("div", null, children),
  CommandGroup: ({ children }: { children: React.ReactNode }) =>
    React.createElement("div", null, children),
  CommandItem: ({
    children,
    onSelect,
  }: {
    children: React.ReactNode;
    onSelect: () => void;
    value?: string;
  }) =>
    React.createElement(
      "button",
      { "data-testid": "cmd-item", onClick: onSelect },
      children,
    ),
}));

import { CommandPalette } from "./command-palette";

const LINKS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/runs", label: "Runs" },
];

afterEach(cleanup);
beforeEach(() => pushMock.mockReset());

describe("CommandPalette", () => {
  it("is closed (renders nothing) by default", () => {
    render(React.createElement(CommandPalette, { links: LINKS }));
    expect(screen.queryByTestId("palette")).toBeNull();
  });

  it("opens on the Cmd/Ctrl-K chord and lists the provided routes", () => {
    render(React.createElement(CommandPalette, { links: LINKS }));
    fireEvent.keyDown(document, { key: "k", metaKey: true });
    expect(screen.getByTestId("palette")).toBeTruthy();
    const items = screen.getAllByTestId("cmd-item");
    expect(items.map((i) => i.textContent)).toEqual(["Dashboard", "Runs"]);
  });

  it("navigates and closes when an item is selected", () => {
    render(React.createElement(CommandPalette, { links: LINKS }));
    fireEvent.keyDown(document, { key: "k", ctrlKey: true });
    fireEvent.click(screen.getAllByTestId("cmd-item")[1]);
    expect(pushMock).toHaveBeenCalledWith("/runs");
    // Selecting closes the palette.
    expect(screen.queryByTestId("palette")).toBeNull();
  });

  it("toggles closed when the chord is pressed again", () => {
    render(React.createElement(CommandPalette, { links: LINKS }));
    fireEvent.keyDown(document, { key: "k", metaKey: true });
    expect(screen.getByTestId("palette")).toBeTruthy();
    fireEvent.keyDown(document, { key: "k", metaKey: true });
    expect(screen.queryByTestId("palette")).toBeNull();
  });
});
