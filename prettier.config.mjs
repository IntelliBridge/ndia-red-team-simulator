/**
 * Config and scripts only. The tree is deliberately not reformatted here and
 * format:check is not gated in CI, because a whole-tree reformat conflicts
 * with the concurrent work in web/ (Risks, Open Questions).
 *
 * @type {import("prettier").Config}
 */
export default {
  plugins: ["prettier-plugin-tailwindcss"],
  tailwindStylesheet: "./web/src/styles/globals.css",
  tailwindFunctions: ["clsx", "cva", "cn"],
};
