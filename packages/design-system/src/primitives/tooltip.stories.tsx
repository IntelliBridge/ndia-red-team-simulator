import type { Meta, StoryObj } from "@storybook/react";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "./tooltip";

const meta: Meta<typeof Tooltip> = {
  component: Tooltip,
  title: "Primitives/Tooltip",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof Tooltip>;

export const Default: Story = {
  render: () => (
    <div className="flex justify-center p-12">
      <Tooltip>
        <TooltipTrigger className="rounded-md border px-4 py-2 text-sm">
          Re-run scan
        </TooltipTrigger>
        <TooltipContent>Queue a fresh scan for this target</TooltipContent>
      </Tooltip>
    </div>
  ),
};

// Demonstrates an explicit, shared TooltipProvider wrapping several
// tooltips (the recommended pattern when many triggers share one delay).
export const SharedProvider: Story = {
  render: () => (
    <TooltipProvider delayDuration={200}>
      <div className="flex justify-center gap-4 p-12">
        <Tooltip>
          <TooltipTrigger className="rounded-md border px-3 py-2 text-sm">
            Verified
          </TooltipTrigger>
          <TooltipContent>Audit chain verified end-to-end</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger className="rounded-md border px-3 py-2 text-sm">
            Severity
          </TooltipTrigger>
          <TooltipContent>CVSS 9.1 — critical</TooltipContent>
        </Tooltip>
      </div>
    </TooltipProvider>
  ),
};
