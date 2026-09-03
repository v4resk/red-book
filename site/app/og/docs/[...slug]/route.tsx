import { getPageImageUrl, source } from '@/lib/source';
import { notFound } from 'next/navigation';
import { ImageResponse } from 'next/og';
import { generate as DefaultImage } from 'fumadocs-ui/og';
import { appName } from '@/lib/shared';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const revalidate = false;

// Supply the OG font from disk. Without an explicit `fonts` option, next/og
// fetches a default font from a CDN while generating each image, so the static
// export fails on any host without outbound network (the Pi, offline CI). The
// file is vendored under fonts/ so the build never touches the network.
const ogFont = readFileSync(join(process.cwd(), 'fonts', 'Geist-Regular.ttf'));

export async function GET(_req: Request, { params }: RouteContext<'/og/docs/[...slug]'>) {
  const { slug } = await params;
  const page = source.getPage(slug.slice(0, -1));
  if (!page) notFound();

  return new ImageResponse(
    <DefaultImage
      title={page.data.title}
      description={page.data.description}
      site={appName}
      // brand red instead of the default magenta; the lifted dark-mode shade
      // reads better on the generator's near-black background
      // dark card with the infiltr8 red as the accent
      primaryColor="rgba(191,4,38,0.45)"
      primaryTextColor="rgb(242,65,95)"
    />,
    {
      width: 1200,
      height: 630,
      fonts: [{ name: 'Geist', data: ogFont, weight: 400, style: 'normal' }],
    },
  );
}

export function generateStaticParams() {
  return source.getPages().map((page) => ({
    lang: page.locale,
    slug: getPageImageUrl(page).segments,
  }));
}
