import type { Preview } from "@storybook/react";
import "../src/app/globals.css";

const preview: Preview = {
  parameters: {
    controls: { matchers: { color: /(background|color)$/i, date: /Date$/ } },
    a11y: { config: { rules: [] } },
    backgrounds: {
      default: "redsim-light",
      values: [
        { name: "redsim-light", value: "#f8fafc" },
        { name: "redsim-dark", value: "#0b1220" },
      ],
    },
  },
};

export default preview;
