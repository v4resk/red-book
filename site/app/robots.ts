import type { MetadataRoute } from 'next';
import { siteUrl } from '@/lib/seo';

// Static export writes this to out/robots.txt at build time.
export const dynamic = 'force-static';

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: '*', allow: '/' }],
    sitemap: `${siteUrl}/sitemap.xml`,
  };
}
