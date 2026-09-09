import type { StorybookConfig } from "@storybook/nextjs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// web/package.json declares "type": "module". Storybook 8 still evaluates this
// file through a CommonJS require hook, so __dirname happens to resolve here
// today, but the import.meta form resolves under both loaders and survives the
// move to a Vite builder.
const here = fileURLToPath(new URL(".", import.meta.url));

const config: StorybookConfig = {
  framework: { name: "@storybook/nextjs", options: {} },
  // Stories live in the design-system workspace so they're co-located
  // with the component they exercise; the web app re-exports the
  // configuration so ``pnpm --filter @redsim/web storybook`` is the
  // single entry point.
  stories: [
    "../../packages/design-system/src/**/*.stories.@(ts|tsx)",
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
      "@redsim/design-system": path.resolve(
        here, "..", "..", "packages", "design-system", "src",
      ),
    };
    return cfg;
  },
  docs: { autodocs: "tag" },
};

export default config;
