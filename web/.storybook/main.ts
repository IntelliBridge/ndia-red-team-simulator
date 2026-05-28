import type { StorybookConfig } from "@storybook/nextjs";
import path from "node:path";

const config: StorybookConfig = {
  framework: { name: "@storybook/nextjs", options: {} },
  // Stories live in the design-system workspace so they're co-located
  // with the component they exercise; the web app re-exports the
  // configuration so ``pnpm --filter @aegis/web storybook`` is the
  // single entry point.
  stories: [
    "../../project_repos/design-system/src/**/*.stories.@(ts|tsx)",
    "../src/**/*.stories.@(ts|tsx)",
  ],
  addons: [
    "@storybook/addon-essentials",
    "@storybook/addon-a11y",
  ],
  typescript: {
    check: false,
    reactDocgen: "react-docgen-typescript",
  },
  webpackFinal: async (cfg) => {
    cfg.resolve = cfg.resolve ?? {};
    cfg.resolve.alias = {
      ...(cfg.resolve.alias as Record<string, string> | undefined),
      "@aegis/design-system": path.resolve(
        __dirname, "..", "..", "project_repos", "design-system", "src",
      ),
    };
    return cfg;
  },
  docs: { autodocs: "tag" },
};

export default config;
