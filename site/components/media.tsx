import * as React from 'react';
import { withBase } from '@/lib/seo';

/** basePath-aware <img>.
 *
 *  MDX only substitutes lowercase intrinsic tags for markdown-generated
 *  elements — one nested inside explicit JSX (e.g. <figure><img/></figure>)
 *  bypasses the components map. A capitalised component always resolves from
 *  scope, so content uses <Img>/<Figure> instead of raw <img>. */
export function Img({ src, alt = '', ...rest }: React.ImgHTMLAttributes<HTMLImageElement>) {
  return <img src={typeof src === 'string' ? withBase(src) : src} alt={alt} {...rest} />;
}

export function Figure({
  src, alt = '', caption, children,
}: {
  src: string; alt?: string; caption?: string; children?: React.ReactNode;
}) {
  // `caption` for plain text; children when the caption contains markup (a
  // link, emphasis...) which cannot live inside a quoted JSX attribute
  const cap = children ?? caption;
  return (
    <figure>
      <Img src={src} alt={alt} />
      {cap ? <figcaption>{cap}</figcaption> : null}
    </figure>
  );
}

/** basePath-aware internal link, for hand-authored JSX in MDX. */
export function A({ href, ...rest }: React.AnchorHTMLAttributes<HTMLAnchorElement>) {
  return <a href={typeof href === 'string' ? withBase(href) : href} {...rest} />;
}
