import type { Meta, StoryObj } from "@storybook/react";
import { FindingCard } from "./finding-card";

const meta: Meta<typeof FindingCard> = {
  component: FindingCard,
  title: "Aegis/FindingCard",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof FindingCard>;

export const Default: Story = {
  args: {
    id: "vuln-0001",
    title: "SQL Injection in Login Form",
    severity: "critical",
    status: "open",
    target: "http://localhost:3000/login",
    validationState: "poc_passed",
    children: "User-supplied email parameter flows directly into an unparameterised query.",
  },
};

export const Pending: Story = {
  args: {
    id: "vuln-0042",
    title: "Reflected XSS on /search",
    severity: "high",
    status: "pending_apply",
    target: "http://localhost:3000/search",
    validationState: "unvalidated",
  },
};
