import * as React from 'react';
import { withBase } from '@/lib/seo';

/** basePath-aware <img>.
 *
 *  MDX only substitutes lowercase intrinsic tags for markdown-generated
 *  elements — one nested inside explicit JSX (e.g. <figure><img/></figure>)
 *  bypasses the components map. A capitalised component always resolves from
 *  scope, so content uses <Img>/<Figure> instead of raw <img>. */
export function Img({ src, alt = '', style, ...rest }: React.ImgHTMLAttributes<HTMLImageElement>) {
  // Content images are centred: a bare block image otherwise sits flush-left,
  // and a <figure>'s UA default (margin: 1em 40px) indents it further.
  return (
    <img
      src={typeof src === 'string' ? withBase(src) : src}
      alt={alt}
      {...rest}
      style={{ display: 'block', marginInline: 'auto', ...style }}
    />
  );
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
    <figure style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', margin: '1rem 0' }}>
      <Img src={src} alt={alt} />
      {cap ? (
        <figcaption style={{ textAlign: 'center', marginTop: '0.5rem', fontSize: '0.875rem' }}>{cap}</figcaption>
      ) : null}
    </figure>
  );
}

/** basePath-aware internal link, for hand-authored JSX in MDX. */
export function A({ href, ...rest }: React.AnchorHTMLAttributes<HTMLAnchorElement>) {
  return <a href={typeof href === 'string' ? withBase(href) : href} {...rest} />;
}
