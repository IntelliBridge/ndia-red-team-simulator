import type { Meta, StoryObj } from "@storybook/react";
import { MriScorecard } from "./mri-scorecard";
const meta: Meta<typeof MriScorecard> = {
  title: "P5/FIXTURE — illustrative/MriScorecard",
  component: MriScorecard,
};
export default meta;
export const Fixture: StoryObj<typeof MriScorecard> = {
  args: {
    score: {
      mri: 72.4,
      grade: "B",
      subscores: {
        S_acc: 80,
        S_asr: 63,
        S_eps: 71,
        S_conf: 68,
        S_expl: 92,
      },
    },
    familyRows: [{ family: "evasion", accuracy: 0.47, n: 47 }],
    curve: [{ eps: 0.01, accuracy: 0.8 }],
  },
};
