import { withBase } from '@/lib/seo';

/** Resource-card favicon. A component rather than a raw <img> so the basePath
 *  prefix is applied at render time and the MDX stays basePath-agnostic. */
export function Favicon({ src, alt = '' }: { src: string; alt?: string }) {
  return <img src={withBase(src)} alt={alt} className="size-5 rounded-sm" />;
}
