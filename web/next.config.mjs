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
  output: 'standalone',
  // The EC2 host rebuilds in place while the previous `next start` keeps
  // serving, and only restarts the unit once the build is done. By default
  // `next build` empties `.next` first, so for the whole build window the
  // old server's HTML points at CSS and chunk files that no longer exist and
  // every page renders unstyled. Keeping the old content-hashed files beside
  // the new ones closes that window; the deploy script clears the generated
  // `.next/types` before building (a deleted route's stale type file would
  // fail the type check) and wipes the directory on a full rebuild. Local
  // builds keep the default so a developer's `.next` does not accumulate.
  cleanDistDir: process.env.REDSIM_WEB_INPLACE_BUILD !== '1',
  experimental: {
    serverActions: { allowedOrigins: ['localhost:3000'] },
  },
};
export default nextConfig;
