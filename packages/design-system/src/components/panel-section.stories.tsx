import type { Meta, StoryObj } from "@storybook/react";
import { PanelSection } from "./panel-section";
const meta: Meta<typeof PanelSection> = {
  title: "P5/FIXTURE — illustrative/PanelSection",
  component: PanelSection,
};
export default meta;
export const Fixture: StoryObj<typeof PanelSection> = {
  args: {
    eyebrow: "FIXTURE — illustrative",
    title: "Campaign evidence",
    children: "Measured content stays inside a named panel.",
  },
};
