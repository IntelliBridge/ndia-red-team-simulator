import type { Meta, StoryObj } from "@storybook/react";
import { MeasurementTable } from "./measurement-table";
const meta: Meta<typeof MeasurementTable> = {
  title: "P5/FIXTURE — illustrative/MeasurementTable",
  component: MeasurementTable,
};
export default meta;
export const Fixture: StoryObj<typeof MeasurementTable> = {
  args: {
    measurements: [
      {
        id: "fixture",
        family: "evasion",
        attack_id: "fgsm",
        n: 47,
        n_correct: 22,
        accuracy: 0.468,
        n_clean_correct: 39,
        attack_success_rate: 0.436,
        pert_first_success_mean: 0.03,
        pert_first_success_n: 17,
        linf_norm_mean: 0.03,
        l2_norm_mean: 0.42,
        wall_time_s: 2.7,
        notes: ["FIXTURE — illustrative"],
        per_class: { vehicle: { n: 19, n_correct: 8 } },
      },
    ],
  },
};
