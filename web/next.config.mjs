/**
 * Importing the env module here fails the build early and by name when a
 * required variable is missing. Docker builds set SKIP_ENV_VALIDATION=1
 * because no runtime value exists at image-build time; the runtime stage does
 * not inherit it, so the schema is live when `next start` boots.
 */
import "./src/env.js";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The Docker image runs the standalone server; the EC2 host runs `next start`
  // on a full build, which Next refuses to combine with a standalone output
  // (its pages/_error module goes missing and every server error falls back to
  // the unstyled static 500 page). Opt in from the Dockerfile only.
  ...(process.env.NEXT_OUTPUT_STANDALONE === '1' ? { output: 'standalone' } : {}),
  experimental: {
    serverActions: { allowedOrigins: ['localhost:3000'] },
  },
};
export default nextConfig;
