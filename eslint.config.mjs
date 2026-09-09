import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/node_modules/**",
      "**/.next/**",
      "**/storybook-static/**",
      "web/next-env.d.ts",
      // Untouched by this PR (KTD3). It has no lint block of its own yet.
      "packages/design-system/**",
      // R18 freezes these two byte for byte against the FastAPI cookie
      // contract. eslint --fix is a whole-tree operation, so they are excluded
      // here rather than trusted not to be rewritten.
      "web/src/server/redsim-session.ts",
      "web/src/server/redsim-session.test.ts",
    ],
  },
  {
    // Everything below is scoped to the Next app. basePath keeps
    // eslint-config-next's rootDir-relative resolution working from the
    // workspace root, where the ESLint binary is installed (KTD5).
    basePath: "web",
    extends: [nextCoreWebVitals, nextTypescript],
    settings: {
      next: { rootDir: "web" },
      // eslint-config-next pulls eslint-plugin-react 7.37, whose version
      // auto-detection calls context.getFilename(), removed in ESLint 10.
      // Naming the version skips that code path.
      react: { version: "18.3" },
    },
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname + "/web",
      },
    },
    linterOptions: { reportUnusedDisableDirectives: true },
    rules: {
      // T3's overrides, verbatim.
      "@typescript-eslint/array-type": "off",
      "@typescript-eslint/consistent-type-definitions": "off",
      "@typescript-eslint/consistent-type-imports": [
        "warn",
        { prefer: "type-imports", fixStyle: "inline-type-imports" },
      ],
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/require-await": "off",
      "@typescript-eslint/no-misused-promises": [
        "error",
        { checksVoidReturn: { attributes: false } },
      ],

      // Downgraded, not disabled, and named here rather than left silent.
      //
      // eslint-config-next is pinned to 16 because 14.x peers eslint ^7 || ^8
      // and 15.x peers ^9, so neither installs beside ESLint 10 (KTD5). Its
      // React Compiler rules are written against React 19 conventions and this
      // app is React 18 on Next 14. The four hits they produce
      // (projects/[slug]/settings, theme-provider, useRequireAuth,
      // useRunEvents) each need a hook rewritten, which is the kind of
      // component rewrite this PR's scope excludes. They stay visible as
      // warnings and belong to the six-major bump that moves React to 19.
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/refs": "warn",
    },
  },
  {
    // Test doubles legitimately reach for `any`: these suites hand deliberately
    // malformed fixtures to code that must survive them, and typing each one
    // would assert the shape the test exists to violate. Kept as an error in
    // application code, where it is a real signal.
    basePath: "web",
    files: ["**/*.test.ts", "**/*.test.tsx"],
    rules: { "@typescript-eslint/no-explicit-any": "warn" },
  },
  {
    // web/tsconfig.json's include is deliberately narrow (src plus
    // next-env.d.ts), so the root configs, the Storybook setup, the vitest
    // setup and the Playwright suite are outside the TypeScript project.
    // Type-aware rules cannot run on a file the project does not contain.
    basePath: "web",
    files: [
      "*.ts",
      "*.js",
      "*.mjs",
      ".storybook/**",
      "vitest.setup*.ts",
      "tests/**",
    ],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: { parserOptions: { projectService: false, project: null } },
  },
);
