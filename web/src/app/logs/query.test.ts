// @vitest-environment node
import { describe, expect, it } from "vitest";

import { buildLogsQuery } from "./query";

type LogsQueryParams = Parameters<typeof buildLogsQuery>[0];

// URLSearchParams is structurally compatible with the ReadonlyURLSearchParams
// arg (both expose .get); the cast keeps the source signature honest.
function searchParams(init?: string): LogsQueryParams {
  return new URLSearchParams(init) as unknown as LogsQueryParams;
}

describe("buildLogsQuery", () => {
  it("returns an empty string when no filters are present", () => {
    expect(buildLogsQuery(searchParams())).toBe("");
  });

  it("serializes a single run filter", () => {
    expect(buildLogsQuery(searchParams("run=run-xyz"))).toBe("run=run-xyz");
  });

  it("serializes all three filters in run/severity/service order", () => {
    const qs = buildLogsQuery(searchParams("service=scanner&severity=error&run=r1"));
    expect(qs).toBe("run=r1&severity=error&service=scanner");
  });

  it("drops empty filter values", () => {
    expect(buildLogsQuery(searchParams("run=&severity=warn"))).toBe("severity=warn");
  });

  it("ignores unknown query keys", () => {
    expect(buildLogsQuery(searchParams("bogus=1&run=r2"))).toBe("run=r2");
  });
});
