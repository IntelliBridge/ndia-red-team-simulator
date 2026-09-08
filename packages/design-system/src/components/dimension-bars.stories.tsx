import type { Meta, StoryObj } from "@storybook/react";
import { DimensionBars } from "./dimension-bars";
const meta: Meta<typeof DimensionBars> = {
  title: "P5/FIXTURE — illustrative/DimensionBars",
  component: DimensionBars,
};
export default meta;
export const Fixture: StoryObj<typeof DimensionBars> = {
  args: {
    values: {
      clean_accuracy: 82.4,
      adversarial_accuracy: 47.8,
      attack_resistance: 61.3,
      confidence_stability: 73.1,
      explanation_stability: 58.6,
    },
  },
};
