import React from "react";
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import RootLayout, { metadata } from "./layout";

afterEach(cleanup);

describe("RootLayout", () => {
  it("renders all six nav links with the correct hrefs", () => {
    render(
      React.createElement(RootLayout, null, React.createElement("div", null, "child-sentinel"))
    );

    const dashboardLink = screen.getByText("Dashboard", { selector: "a" });
    expect(dashboardLink.getAttribute("href")).toBe("/dashboard");

    const projectsLink = screen.getByText("Projects", { selector: "a" });
    expect(projectsLink.getAttribute("href")).toBe("/projects");

    const targetsLink = screen.getByText("Targets", { selector: "a" });
    expect(targetsLink.getAttribute("href")).toBe("/targets");

    const costLink = screen.getByText("Cost", { selector: "a" });
    expect(costLink.getAttribute("href")).toBe("/cost");

    const logsLink = screen.getByText("Logs", { selector: "a" });
    expect(logsLink.getAttribute("href")).toBe("/logs");

    const auditLink = screen.getByText("Audit", { selector: "a" });
    expect(auditLink.getAttribute("href")).toBe("/audit");
  });

  it("renders passed children inside the layout", () => {
    render(
      React.createElement(RootLayout, null, React.createElement("div", null, "child-sentinel"))
    );
    expect(screen.getByText("child-sentinel")).toBeTruthy();
  });

  it("exported metadata has a truthy title equal to the defined string", () => {
    expect(metadata.title).toBeTruthy();
    expect(metadata.title).toBe("Aegis");
  });

  it("exported metadata has a truthy description", () => {
    expect(metadata.description).toBeTruthy();
    expect(metadata.description).toBe("Aegis security platform");
  });
});
