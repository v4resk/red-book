import defaultMdxComponents from 'fumadocs-ui/mdx';
import * as TabsComponents from 'fumadocs-ui/components/tabs';
import * as CardComponents from 'fumadocs-ui/components/card';
import { Callout } from 'fumadocs-ui/components/callout';
import type { MDXComponents } from 'mdx/types';
import type { ImgHTMLAttributes } from 'react';
import * as React from 'react';
import { Favicon } from '@/components/favicon';
import { A, Figure, Img } from '@/components/media';
import { ResourceCard } from '@/components/resource-card';
import { withBase } from '@/lib/seo';

export function getMDXComponents(components?: MDXComponents) {
  return {
    ...defaultMdxComponents,
    // GitBook -> Fumadocs conversion emits these: 662 <Tabs>, 1432 <Tab>,
    // 815 <Card>, 484 <Callout>
    // raw <img src="/assets/…"> in MDX is emitted verbatim by Next, so prefix
    // basePath here rather than baking it into 558 content files
    img: ({ src, ...rest }: ImgHTMLAttributes<HTMLImageElement>) => (
      <img src={typeof src === 'string' ? withBase(src) : src} {...rest} />
    ),
    Favicon,
    ResourceCard,
    Img,
    Figure,
    A,
    ...TabsComponents,
    ...CardComponents,
    // Fumadocs' Card renders a plain <a>, so an internal href needs basePath.
    // External resource-card hrefs (http…) pass through untouched.
    Card: ({ href, ...rest }: React.ComponentProps<typeof CardComponents.Card>) => (
      <CardComponents.Card
        href={typeof href === 'string' ? withBase(href) : href}
        {...rest}
      />
    ),
    Callout,
    ...components,
  } satisfies MDXComponents;
}

export const useMDXComponents = getMDXComponents;

declare global {
  type MDXProvidedComponents = ReturnType<typeof getMDXComponents>;
}
