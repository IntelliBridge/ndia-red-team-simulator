import type { Meta, StoryObj } from "@storybook/react";
import { StageTimeline } from "./stage-timeline";

const meta: Meta<typeof StageTimeline> = {
  component: StageTimeline,
  title: "Redsim/StageTimeline",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof StageTimeline>;

export const Mixed: Story = {
  args: {
    stages: [
      {
        name: "target.up",
        mode: "live",
        success: true,
        detail: "juice-shop on http://localhost:3000",
      },
      {
        name: "scan.start",
        mode: "live",
        success: true,
        detail: "scanner returned 3 finding(s)",
      },
      {
        name: "remediate",
        mode: "golden_patch",
        success: true,
        detail: "vuln-0001 fixed via fixture",
      },
      {
        name: "report",
        mode: "live",
        success: true,
        detail: "report.{md,json,html} written",
      },
    ],
  },
};

export const PartialFailure: Story = {
  args: {
    stages: [
      { name: "target.up", mode: "live", success: true, detail: "ok" },
      {
        name: "scan.start",
        mode: "live",
        success: false,
        detail: "scanner exited rc=2; 1 finding emitted (partial)",
      },
      {
        name: "remediate",
        mode: "fixture",
        success: true,
        detail: "golden patch applied",
      },
    ],
  },
};
