import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

/** @type {import('next').NextConfig} */
// Served at https://infiltr8.io/redbook/ behind a reverse proxy. basePath is
// required even so: without it the emitted HTML references /_next/... and
// /assets/... which the browser resolves against infiltr8.io/ (the landing
// page), not the book. The proxy passes /redbook/* through unchanged.
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '/redbook';

const config = {
  output: 'export',
  basePath,
  trailingSlash: true,
  reactStrictMode: true,
  // `output: export` ships no server, so /_next/image (the optimizer endpoint)
  // 404s and every <Image> breaks. Serve the files as-is instead.
  images: { unoptimized: true },
};

export default withMDX(config);
