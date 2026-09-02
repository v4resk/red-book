import type { MetadataRoute } from 'next';
import { source } from '@/lib/source';
import { absolute } from '@/lib/seo';

export const dynamic = 'force-static';

export default function sitemap(): MetadataRoute.Sitemap {
  return source.getPages().map((page) => ({
    url: absolute(page.url),
    changeFrequency: 'weekly' as const,
    // the landing page outranks sections, which outrank leaf pages
    priority: page.url === '/' ? 1 : page.slugs.length <= 1 ? 0.8 : 0.6,
  }));
}
