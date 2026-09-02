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
    // Raw <img src="/assets/…"> in MDX is emitted verbatim by Next, so the
    // basePath has to be added here rather than baked into 558 content files.
    //
    // Markdown images (![](…)) are rewritten by remark-image into a static
    // import OBJECT, not a string. Those must go to Fumadocs' own image
    // component (which handles basePath itself); rendering them as a raw <img>
    // stringifies the object into src="[object Object]".
    img: (props: ImgHTMLAttributes<HTMLImageElement>) => {
      if (typeof props.src !== 'string') {
        const Default = defaultMdxComponents.img as React.ComponentType<typeof props>;
        return <Default {...props} />;
      }
      return <img {...props} src={withBase(props.src)} />;
    },
    Favicon,
    ResourceCard,
    Img,
    Figure,
    A,
    ...TabsComponents,
    ...CardComponents,
    Callout,
    ...components,
  } satisfies MDXComponents;
}

export const useMDXComponents = getMDXComponents;

declare global {
  type MDXProvidedComponents = ReturnType<typeof getMDXComponents>;
}
