import type { Meta, StoryObj } from "@storybook/react";
import { AuditChainBadge } from "./audit-chain-badge";

const meta: Meta<typeof AuditChainBadge> = {
  component: AuditChainBadge,
  title: "Aegis/AuditChainBadge",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof AuditChainBadge>;

export const Verified: Story = {
  args: { state: "verified", events: 42, chainId: "run:run-abc123" },
};
export const Broken: Story = {
  args: { state: "broken", events: 17, chainId: "project:proj-a" },
};
export const Pending: Story = {
  args: { state: "pending" },
};
