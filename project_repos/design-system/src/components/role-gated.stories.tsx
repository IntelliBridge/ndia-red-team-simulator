import type { Meta, StoryObj } from "@storybook/react";
import { RoleGated } from "./role-gated";

const meta: Meta<typeof RoleGated> = {
  component: RoleGated,
  title: "Aegis/RoleGated",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof RoleGated>;

export const ScannerSeesNothing: Story = {
  args: {
    minRole: "approver",
    callerRole: "scanner",
    children: "👀 Apply Patch button (hidden)",
    fallback: "(no access)",
  },
};

export const ApproverSees: Story = {
  args: {
    minRole: "approver",
    callerRole: "approver",
    children: "✅ Apply Patch button (visible)",
  },
};

export const AdminAlwaysSees: Story = {
  args: {
    minRole: "admin",
    callerRole: "admin",
    children: "🛠 Admin-only control",
  },
};
