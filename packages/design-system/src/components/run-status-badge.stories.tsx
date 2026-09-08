import type { Meta, StoryObj } from "@storybook/react";
import { RunStatusBadge } from "./run-status-badge";

const meta: Meta<typeof RunStatusBadge> = {
  component: RunStatusBadge,
  title: "Redsim/RunStatusBadge",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof RunStatusBadge>;

export const Queued: Story = { args: { status: "queued" } };
export const Running: Story = { args: { status: "running" } };
export const Succeeded: Story = { args: { status: "succeeded" } };
export const PartialSuccess: Story = { args: { status: "partial_success" } };
export const Failed: Story = { args: { status: "failed" } };
export const Cancelled: Story = { args: { status: "cancelled" } };
