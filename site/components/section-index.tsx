import Link from 'next/link';
import { ChevronRight } from 'lucide-react';

export interface SectionChild {
  url: string;
  title: string;
  description?: string;
  wip?: boolean;
}

/** Auto-generated contents listing for a section's index page.
 *
 *  Most index pages exist only to open a sidebar folder and would otherwise
 *  render blank: a dead end for readers and thin content for crawlers. This
 *  lists the section's direct children so every index page has real, linked
 *  content. Prose authored above it in the MDX is kept and shown first. */
export function SectionIndex({ items }: { items: SectionChild[] }) {
  if (!items.length) return null;
  return (
    <div className="not-prose mt-6 grid gap-2 sm:grid-cols-2">
      {items.map((it) => (
        <Link
          key={it.url}
          href={it.url}
          className="flex items-center gap-3 rounded-lg border bg-fd-card px-3 py-2.5 text-fd-card-foreground no-underline transition-colors hover:bg-fd-accent/60"
        >
          <span className="flex min-w-0 flex-1 flex-col leading-tight">
            <span className="truncate text-sm font-medium text-fd-foreground">
              {it.title}
              {it.wip ? (
                <span className="ms-2 rounded bg-fd-muted px-1.5 py-0.5 align-middle text-[10px] font-normal text-fd-muted-foreground">
                  WIP
                </span>
              ) : null}
            </span>
            {it.description ? (
              <span className="truncate text-xs text-fd-muted-foreground">{it.description}</span>
            ) : null}
          </span>
          <ChevronRight className="size-4 shrink-0 text-fd-muted-foreground" aria-hidden />
        </Link>
      ))}
    </div>
  );
}
