import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Unit-test config for the app code (src/) plus the project-root config
// modules (.storybook/*, playwright.config, vitest.setup). The Playwright
// e2e suite under tests/ is intentionally excluded (it owns its own runner
// via playwright.config.ts) — none of the include globs reach tests/.
// Default env is jsdom for the browser-side auth client; server modules opt
// into node via a `// @vitest-environment node` docblock.
export default defineConfig({
  test: {
    environment: "jsdom",
    include: [
      "src/**/*.{test,spec}.{ts,tsx}",
      ".storybook/**/*.{test,spec}.{ts,tsx}",
      "playwright.config.{test,spec}.ts",
      "vitest.setup.{test,spec}.ts",
    ],
    setupFiles: ["./vitest.setup.ts"],
    css: false,
  },
  // No @vitejs/plugin-react here, so configure esbuild to emit the automatic
  // JSX runtime — component/page tests render via @testing-library/react
  // without needing a `React` import in every .tsx test file.
  // oxc: false lets vite fall back to esbuild so the jsx setting below takes
  // effect; vitest v4 / vite v8 enables oxc by default which would otherwise
  // override esbuild and fail to parse JSX in .tsx files.
  oxc: false,
  esbuild: {
    jsx: "automatic",
  },
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
});
