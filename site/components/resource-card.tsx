import { ChevronRight } from 'lucide-react';
import { withBase } from '@/lib/seo';

/** External resource link.
 *
 *  Purpose-built rather than restyling Fumadocs' <Card>: that wraps the icon in
 *  a bordered chip (w-fit, p-1.5, mb-2) and stacks it above the title, which
 *  can't be reshaped into a single row without fighting every utility on it.
 *
 *  Layout: [icon] [title / domain] [chevron] — one row, icon centred against
 *  the text block, fixed icon box so cards without a favicon keep alignment.
 */
export function ResourceCard({
  href, title, description, icon,
}: {
  href: string; title: string; description?: string; icon?: string;
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      className="not-prose my-2 flex items-center gap-3 rounded-lg border bg-fd-card px-3 py-2.5 text-fd-card-foreground no-underline transition-colors hover:bg-fd-accent/60"
    >
      {/* fixed box, always rendered: a missing favicon must not shift the text */}
      <span className="flex size-7 shrink-0 items-center justify-center overflow-hidden rounded-md border bg-fd-muted">
        {icon ? (
          <img src={withBase(icon)} alt="" loading="lazy" className="size-4 rounded-sm" />
        ) : null}
      </span>

      {/* min-w-0 lets the children truncate instead of stretching the row */}
      <span className="flex min-w-0 flex-1 flex-col leading-tight">
        <span className="truncate text-sm font-medium text-fd-foreground">{title}</span>
        {description ? (
          <span className="truncate text-xs text-fd-muted-foreground">{description}</span>
        ) : null}
      </span>

      <ChevronRight className="size-4 shrink-0 text-fd-muted-foreground" aria-hidden />
    </a>
  );
}
