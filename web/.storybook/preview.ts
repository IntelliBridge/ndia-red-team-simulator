import type { Preview } from "@storybook/react";
import "../src/styles/globals.css";

const preview: Preview = {
  parameters: {
    controls: { matchers: { color: /(background|color)$/i, date: /Date$/ } },
    a11y: { config: { rules: [] } },
    // One dark theme (labs.agiledefense.com): the page ground and the card
    // surface, so a story can be checked against both.
    backgrounds: {
      default: "redsim-navy",
      values: [
        { name: "redsim-navy", value: "#04060f" },
        { name: "redsim-surface", value: "#0f1f36" },
      ],
    },
  },
};

export default preview;
