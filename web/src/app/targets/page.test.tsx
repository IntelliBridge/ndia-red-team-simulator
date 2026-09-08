import { createElement } from "react";
import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

const replace = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ replace }) }));

import TargetsPage from "./page";

describe("/targets redirect", () => {
  it("redirects the obsolete target surface to the model catalog", () => {
    render(createElement(TargetsPage));
    expect(replace).toHaveBeenCalledWith("/models");
  });
});
