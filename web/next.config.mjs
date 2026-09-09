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
  experimental: {
    serverActions: { allowedOrigins: ['localhost:3000'] },
  },
};
export default nextConfig;
