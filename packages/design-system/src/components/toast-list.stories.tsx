import type { Meta, StoryObj } from "@storybook/react";
import { ToastList } from "./toast-list";

const meta: Meta<typeof ToastList> = {
  component: ToastList,
  title: "Redsim/ToastList",
  tags: ["autodocs"],
};
export default meta;

type Story = StoryObj<typeof ToastList>;

export const Stack: Story = {
  args: {
    toasts: [
      {
        id: "1",
        tone: "success",
        title: "Scan started",
        description: "run-abc123 queued",
      },
      {
        id: "2",
        tone: "warning",
        title: "Budget nearing limit",
        description: "$0.42 of $0.50 used today",
      },
      { id: "3", tone: "info", title: "Session refreshed" },
    ],
  },
};
