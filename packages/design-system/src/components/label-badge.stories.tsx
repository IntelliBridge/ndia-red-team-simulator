import type { Meta, StoryObj } from "@storybook/react";
import { LabelBadge } from "./label-badge";
const meta: Meta<typeof LabelBadge> = {
  title: "P5/FIXTURE — illustrative/LabelBadge",
  component: LabelBadge,
};
export default meta;
export const Fixture: StoryObj<typeof LabelBadge> = {
  args: { variant: "candidate" },
};
