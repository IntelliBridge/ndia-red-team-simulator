// Tailwind v3 plugin pair. An ESM default export because web/package.json
// declares "type": "module", under which a module.exports config throws at
// config load for every build, test run and Storybook start.
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
