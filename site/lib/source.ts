import { loader } from 'fumadocs-core/source';
import { docsContentRoute, docsImageRoute, docsRoute } from './shared';
import { defineDocs } from 'fumadocs-mdx/macro';
import { metaSchema, pageSchema } from 'fumadocs-core/source/schema';
import { z } from 'zod';
import { createElement } from 'react';
import { Construction } from 'lucide-react';
import { absolute } from './seo';

const docs = defineDocs({
  dir: 'content/docs',
  docs: {
    // `wip: true` in a page's frontmatter marks it work-in-progress: it draws
    // a sidebar icon and an in-page banner. Replaces the GitBook convention of
    // putting a hammer emoji in the title.
    schema: pageSchema.extend({ wip: z.boolean().optional() }),
    files: ['**/*.mdx'],
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
  meta: {
    schema: metaSchema,
  },
});

// See https://fumadocs.dev/docs/headless/source-api for more info
export const source = loader({
  baseUrl: docsRoute,
  source: docs.toFumadocsSource(),
  // frontmatter `icon:` is a string; resolve the ones we use to components
  icon(name) {
    if (name === 'Construction') return createElement(Construction);
  },
  plugins: [],
});

export function getPageImageUrl(page: (typeof source)['$inferPage']) {
  const segments = [...page.slugs, 'image.png'];

  return {
    segments,
    url: '/' + [page.locale, ...docsImageRoute.split('/'), ...segments].filter(Boolean).join('/'),
  };
}

export function getPageMarkdownUrl(page: (typeof source)['$inferPage']) {
  const segments = [...page.slugs, 'content.md'];

  return {
    segments,
    url: '/' + [page.locale, ...docsContentRoute.split('/'), ...segments].filter(Boolean).join('/'),
  };
}

export async function getLLMText(page: (typeof source)['$inferPage']) {
  const processed = await page.data.getText('processed');

  // absolute URL: an LLM consuming llms-full.txt has no basePath context
  return `# ${page.data.title} (${absolute(page.url)})

${processed}`;
}
