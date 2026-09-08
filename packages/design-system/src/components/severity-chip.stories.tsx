import type { Meta, StoryObj } from "@storybook/react";
import { SeverityChip } from "./severity-chip";

const meta: Meta<typeof SeverityChip> = {
  component: SeverityChip,
  title: "Redsim/SeverityChip",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof SeverityChip>;

export const Critical: Story = { args: { level: "critical" } };
export const High: Story = { args: { level: "high" } };
export const Medium: Story = { args: { level: "medium" } };
export const Low: Story = { args: { level: "low" } };
export const Info: Story = { args: { level: "info" } };
export const Unknown: Story = { args: { level: "weird-other-value" } };
