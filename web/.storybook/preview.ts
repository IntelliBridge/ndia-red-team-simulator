import type { Preview } from "@storybook/react";
import "../src/app/globals.css";

const preview: Preview = {
  parameters: {
    controls: { matchers: { color: /(background|color)$/i, date: /Date$/ } },
    a11y: { config: { rules: [] } },
    backgrounds: {
      default: "aegis-light",
      values: [
        { name: "aegis-light", value: "#f8fafc" },
        { name: "aegis-dark", value: "#0b1220" },
      ],
    },
  },
};

export default preview;
