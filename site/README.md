# The Red-Book — self-hosted site (Fumadocs)

Static Next.js / Fumadocs build of The Red-Book.

    npm install
    npm run build      # -> out/
    npm start          # serve out/

`content/docs/**.mdx` is the **source of truth**. Edit it directly — this is a
standard Fumadocs project, so the usual conventions apply.

## Structure

    content/docs/**.mdx   the book: one file per page
    content/docs/meta.json  per-folder nav (title, order, defaultOpen)
    public/assets/        images, favicons
    app/ components/ lib/ the Fumadocs app

## URLs

Routes mirror `content/docs/`, and the tree was laid out so every page keeps the
URL it had on GitBook (verified 557/557 against the old sitemap). A folder's
`index.mdx` serves the folder path itself, e.g.
`content/docs/redteam/recon/index.mdx` → `/redteam/recon`.

`meta.json` controls navigation:

    { "title": "Reconnaissance", "pages": ["dns-enum", "...", "..."] }

`pages` is an allowlist and also sets the order; the trailing `"..."` is a
rest operator that includes anything not listed, so a new page always shows up
even if you forget to add it. Note two asymmetric rules:

- **folders** must NOT list `index` — listing it makes Fumadocs treat the page
  as an ordinary child and leaves the folder header a dead toggle
- the **root** must list `index` first, or the intro page sorts last

## Resource links

`<Card href="https://…">` renders with the target's real title and favicon.
That metadata lives in `link-meta.json` and `public/assets/favicons/`, both
committed, so builds are offline and deterministic — no third-party host can
break a build.

After adding new resource links:

    npm run links      # fetch only the new URLs, then rewrite the cards

Other entry points:

    npm run links:apply    # re-render cards from the cache, no network
    npm run links:refresh  # re-fetch everything (e.g. titles changed)

CI runs `npm run links` before each build and commits any new metadata, so in
practice this is automatic. The fetcher is incremental and checkpoints every 25
URLs, so an interrupted run resumes. Links it can't resolve (JS-rendered or
bot-blocked sites) fall back to the bare domain — still a valid card.

## Notes

- `images: { unoptimized: true }` is required: `output: 'export'` ships no
  server, so the `/_next/image` optimiser endpoint would 404.
- Tailwind is told `@source not "../content"` — the 558 content files carry no
  utility classes, and scanning them is expensive. `@source "../overrides"` was
  removed with the overrides mechanism. **`@source` paths are relative to
  `app/global.css`, not the project root.**
- The accent colour is the infiltr8 red sampled from the logo (`#bf0426`),
  lifted to `#f2415f` in dark mode for contrast.
- Sidebar depth is styled via the inline `padding-inline-start:
  calc(N * var(--spacing))` that Fumadocs emits (N = 2, 5, 8, 11 — three per
  level); N=2 uniquely selects top-level categories. If a Fumadocs upgrade
  changes that spacing scale, this is the selector to revisit.

## History

Converted from the GitBook markdown that lives at the repo root. The converter
(`convert.py`) was removed once the MDX became the source of truth — see the
migration commits for what it handled (GitBook tabs/hints/embeds, Shiki
language normalisation, oversized code fences, dot-prefixed filenames, and the
233 broken links inherited from the GitBook export, all now resolved).
