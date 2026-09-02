/** Single source of truth for the public origin used in SEO metadata. */
export const origin = (
  process.env.NEXT_PUBLIC_SITE_URL ?? 'https://infiltr8.io'
).replace(/\/$/, '');

/** Must match next.config.mjs basePath. */
export const basePath = (process.env.NEXT_PUBLIC_BASE_PATH ?? '/redbook').replace(/\/$/, '');

/** Public origin + base path, e.g. https://infiltr8.io/redbook */
export const siteUrl = `${origin}${basePath}`;

export const siteName = 'Infiltr8: The Red-Book';
export const siteDescription =
  'The Art of Offensive CyberSecurity — technical notes and cheat sheets on red teaming, ' +
  'Active Directory, web, network, cloud and smart-contract security.';

/** Prefix basePath onto a site-absolute path.
 *
 *  Next only injects basePath into next/link and next/image. Raw <img src="/…">
 *  and metadata strings are emitted verbatim, so anything hand-written must go
 *  through here or it resolves against the domain root. */
export function withBase(path: string): string {
  if (!path.startsWith('/') || path.startsWith(basePath + '/')) return path;
  return `${basePath}${path}`;
}

/** Fumadocs page urls are basePath-relative ('/redteam/recon'), so the public
 *  URL is origin + basePath + page url. Next does NOT prefix metadata strings
 *  with basePath, so these must be built explicitly. */
export function absolute(path: string): string {
  return `${siteUrl}${path.startsWith('/') ? path : `/${path}`}`.replace(/\/$/, '') || siteUrl;
}

/** JSON-LD <script>; data is serialised, never interpolated from user input. */
export function jsonLd(data: object) {
  return {
    type: 'application/ld+json',
    dangerouslySetInnerHTML: { __html: JSON.stringify(data) },
  };
}

export function techArticle(o: {
  title: string; description?: string; url: string;
}) {
  return {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: o.title,
    description: o.description,
    url: absolute(o.url),
    isPartOf: { '@type': 'WebSite', name: siteName, url: siteUrl },
    publisher: { '@type': 'Organization', name: 'infiltr8', url: siteUrl },
  };
}

export function breadcrumbs(items: { name: string; url: string }[]) {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map((it, i) => ({
      '@type': 'ListItem',
      position: i + 1,
      name: it.name,
      item: absolute(it.url),
    })),
  };
}
