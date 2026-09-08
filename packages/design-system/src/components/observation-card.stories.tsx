import type { Meta, StoryObj } from "@storybook/react";
import { ObservationCard } from "./observation-card";

const meta: Meta<typeof ObservationCard> = {
  title: "P5/FIXTURE — illustrative/ObservationCard",
  component: ObservationCard,
};
export default meta;

export const Fixture: StoryObj<typeof ObservationCard> = {
  args: {
    artifactUrl: (id) => `/fixture/${id}`,
    observation: {
      id: "o.003",
      sample_index: 3,
      true_label: "truck",
      pred_clean: "truck",
      pred_adv: "car",
      confidence_clean: 0.92,
      confidence_adv: 0.61,
      artifacts: {
        clean: "a-clean",
        adversarial: "a-adv",
        shap_clean: "a-shap-clean",
        shap_adversarial: "a-shap-adv",
      },
      artifact_sha256: {},
      center_mass_ratio_clean: 0.44,
      center_mass_ratio_adv: 0.27,
      metric_kind: "heuristic",
      metric_note: "FIXTURE — illustrative center-mass metric note",
    },
  },
};
