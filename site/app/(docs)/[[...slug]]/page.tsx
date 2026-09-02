import { getPageImageUrl, getPageMarkdownUrl, source } from '@/lib/source';
import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
  MarkdownCopyButton,
  ViewOptionsPopover,
} from 'fumadocs-ui/layouts/docs/page';
import { notFound } from 'next/navigation';
import { getMDXComponents } from '@/components/mdx';
import type { Metadata } from 'next';
import { createRelativeLink } from 'fumadocs-ui/mdx';
import { Callout } from 'fumadocs-ui/components/callout';
import { gitConfig } from '@/lib/shared';
import { absolute, breadcrumbs, jsonLd, siteName, techArticle } from '@/lib/seo';

export default async function Page(props: PageProps<'/[[...slug]]'>) {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const MDX = page.data.body;
  const markdownUrl = getPageMarkdownUrl(page).url;

  // breadcrumb trail from the page's slug chain; unresolved ancestors (a
  // '## group' heading has no page of its own) are skipped
  const crumbs: { name: string; url: string }[] = [{ name: 'The Red-Book', url: '/' }];
  for (let i = 1; i <= page.slugs.length; i++) {
    const ancestor = source.getPage(page.slugs.slice(0, i));
    if (ancestor) crumbs.push({ name: ancestor.data.title, url: ancestor.url });
  }

  return (
    <>
    <script {...jsonLd(techArticle({
      title: page.data.title,
      description: page.data.description,
      url: page.url,
    }))} />
    <script {...jsonLd(breadcrumbs(crumbs))} />
    <DocsPage toc={page.data.toc} full={page.data.full}>
      {page.data.wip ? (
        <Callout type="warn" title="Work in progress">
          This page is incomplete — content may be missing or unverified.
        </Callout>
      ) : null}
      <DocsTitle>{page.data.title}</DocsTitle>
      <DocsDescription className="mb-0">{page.data.description}</DocsDescription>
      <div className="flex flex-row gap-2 items-center border-b pb-6">
        <MarkdownCopyButton markdownUrl={markdownUrl} />
        <ViewOptionsPopover
          markdownUrl={markdownUrl}
          githubUrl={`https://github.com/${gitConfig.user}/${gitConfig.repo}/blob/${gitConfig.branch}/content/docs/${page.path}`}
        />
      </div>
      <DocsBody>
        <MDX
          components={getMDXComponents({
            // this allows you to link to other pages with relative file paths
            a: createRelativeLink(source, page),
          })}
        />
      </DocsBody>
    </DocsPage>
  </>
  );
}

export async function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata(props: PageProps<'/[[...slug]]'>): Promise<Metadata> {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const url = page.url;
  const image = getPageImageUrl(page).url;

  return {
    title: page.data.title,
    description: page.data.description,
    // canonical on every page, even without duplicates -- best practice, and
    // it pins the preferred host if the site is ever reachable on two
    alternates: { canonical: absolute(url) },
    openGraph: {
      type: 'article',
      siteName,
      title: page.data.title,
      description: page.data.description,
      url: absolute(url),
      images: absolute(image),
    },
    twitter: {
      card: 'summary_large_image',
      title: page.data.title,
      description: page.data.description,
      images: absolute(image),
    },
  };
}
