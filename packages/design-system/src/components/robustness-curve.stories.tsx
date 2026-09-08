import type { Meta, StoryObj } from "@storybook/react";
import { RobustnessCurve } from "./robustness-curve";
const meta: Meta<typeof RobustnessCurve> = {
  title: "P5/FIXTURE — illustrative/RobustnessCurve",
  component: RobustnessCurve,
};
export default meta;
export const Fixture: StoryObj<typeof RobustnessCurve> = {
  args: {
    points: [
      {
        family: "evasion",
        attack_id: "fgsm",
        eps: 0.01,
        accuracy: 0.82,
        n: 50,
        n_correct: 41,
      },
      {
        family: "evasion",
        attack_id: "fgsm",
        eps: 0.03,
        accuracy: 0.71,
        n: 50,
        n_correct: 35,
      },
      {
        family: "evasion",
        attack_id: "fgsm",
        eps: 0.1,
        accuracy: 0.48,
        n: 50,
        n_correct: 24,
      },
    ],
  },
};
