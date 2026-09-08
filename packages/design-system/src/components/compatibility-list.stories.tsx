import type { Meta, StoryObj } from "@storybook/react";
import { CompatibilityList } from "./compatibility-list";
const meta: Meta<typeof CompatibilityList> = {
  title: "P5/FIXTURE — illustrative/CompatibilityList",
  component: CompatibilityList,
};
export default meta;
export const Fixture: StoryObj<typeof CompatibilityList> = {
  args: {
    items: ["seed: equal", "dataset revision: equal", "sample indices: equal"],
  },
};
