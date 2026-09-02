#!/usr/bin/env python3
"""Validate the BUILT site. Run after `next build`; exits non-zero on any fault.

Checks the rendered HTML rather than the MDX source, because most breakage so
far has come from the gap between the two: a link can be correct in the source
and wrong on the page (basePath applied twice, a component stringifying an
object, an anchor that only exists in one of two competing forms).

Every check below exists because that exact fault shipped at least once.
"""
import os, re, sys, urllib.parse
from collections import defaultdict

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')
BASE = os.environ.get('NEXT_PUBLIC_BASE_PATH', '/redbook').rstrip('/')

def html_files():
    for root, _, files in os.walk(OUT):
        for fn in files:
            if fn.endswith('.html'):
                yield os.path.join(root, fn)

def route_of(path):
    rel = os.path.relpath(path, OUT)
    rel = rel[:-len('index.html')] if rel.endswith('index.html') else rel[:-len('.html')]
    return '/' + rel.strip('/')

def local_path(url):
    """Map a site URL back to a file in out/, or None if external."""
    if url.startswith(('http://', 'https://', 'mailto:', 'data:', '#')):
        return None
    u = urllib.parse.unquote(url.split('#')[0].split('?')[0])
    if not u.startswith('/'):
        return None
    if BASE and u.startswith(BASE + '/'):
        u = u[len(BASE):]
    elif BASE and u == BASE:
        u = '/'
    return os.path.join(OUT, u.lstrip('/'))

def main():
    if not os.path.isdir(OUT):
        print('no out/ directory; run `npm run build` first'); return 1

    pages = list(html_files())
    routes = {route_of(p) for p in pages}
    faults = defaultdict(list)
    anchors_by_route = {}

    for p in pages:
        h = open(p, encoding='utf-8', errors='replace').read()
        route = route_of(p)
        anchors_by_route[route] = set(re.findall(r'\sid="([^"]+)"', h))

        for attr, url in re.findall(r'\s(href|src)="([^"]*)"', h):
            # 1. an object stringified into an attribute
            if '[object' in url:
                faults['object-stringified'].append(f'{route}  {attr}="{url}"')
                continue
            if url.startswith(('http://', 'https://', 'mailto:', 'data:', '#', '//')) or not url:
                continue
            # 2. basePath applied twice
            if BASE and url.startswith(f'{BASE}{BASE}/'):
                faults['double-basepath'].append(f'{route}  {url}')
                continue
            # 3. site-absolute URL missing basePath
            if BASE and url.startswith('/') and not url.startswith(BASE + '/') and url != BASE:
                faults['missing-basepath'].append(f'{route}  {url}')
                continue
            # 3b. relative internal link. Next emits every internal link as a
            # basePath-absolute URL, so a bare relative href is an unconverted
            # source link (classically a leftover GitBook `foo/bar.md`). These
            # were invisible before because local_path() skipped anything not
            # starting with '/'. Resolve against the page's own directory.
            if not url.startswith('/'):
                rel = urllib.parse.unquote(url.split('#')[0].split('?')[0])
                if rel:
                    cand = os.path.normpath(os.path.join(os.path.dirname(p), rel))
                    if os.path.isdir(cand):
                        cand = os.path.join(cand, 'index.html')
                    if not os.path.exists(cand):
                        faults['dead-relative'].append(f'{route}  {attr}="{url}"')
                continue
            # 4. target does not exist on disk
            lp = local_path(url)
            if lp is None:
                continue
            if os.path.isdir(lp):
                lp = os.path.join(lp, 'index.html')
            if not os.path.exists(lp):
                faults['dead-target'].append(f'{route}  {url}')

    # 5. in-page anchors that point at no element.
    #
    # Fumadocs' own "On this page" panel is excluded: it builds the TOC from the
    # MDX AST, so a heading inside a <Tab> is listed even though only the active
    # tab renders into the DOM. That is a framework behaviour, not a broken
    # content link, and it is reported separately by `tab-heading` below.
    for p in pages:
        h = open(p, encoding='utf-8', errors='replace').read()
        route = route_of(p)
        h_content = re.sub(r'<a data-active="[^"]*" href="#[^"]*"[^>]*>.*?</a>', '', h, flags=re.S)
        for url in re.findall(r'\shref="([^"]*#[^"]*)"', h_content):
            frag = urllib.parse.unquote(url.split('#', 1)[1])
            if not frag:
                continue
            target = url.split('#')[0]
            tr = route if not target else (
                target[len(BASE):].rstrip('/') or '/' if BASE and target.startswith(BASE) else target.rstrip('/'))
            if tr in anchors_by_route and frag not in anchors_by_route[tr]:
                faults['dead-anchor'].append(f'{route}  ->  {url}')

    # informational: headings nested in <Tabs> get a TOC entry with no target
    docs = os.path.join(os.path.dirname(OUT), 'content', 'docs')
    tabbed = 0
    for root, _, files in os.walk(docs):
        for fn in files:
            if not fn.endswith('.mdx'):
                continue
            depth = 0
            for line in open(os.path.join(root, fn), encoding='utf-8').read().split('\n'):
                if re.match(r'^\s*<Tabs\b', line):
                    depth += 1
                elif re.match(r'^\s*</Tabs>', line):
                    depth = max(0, depth - 1)
                elif depth and re.match(r'^#{2,6} ', line):
                    tabbed += 1

    total = sum(len(v) for v in faults.values())
    print(f'verify: {len(pages)} pages, {len(routes)} routes')
    for kind in ('object-stringified', 'double-basepath', 'missing-basepath',
                 'dead-relative', 'dead-target', 'dead-anchor'):
        items = faults.get(kind, [])
        print(f'  {kind:20} {len(items)}')
        for x in items[:8]:
            print(f'      {x}')
        if len(items) > 8:
            print(f'      ... and {len(items) - 8} more')
    if tabbed:
        print(f'  (info) headings inside <Tabs>: {tabbed} -- these appear in the'
              f' TOC but have no DOM target until their tab is selected')
    print('OK' if total == 0 else f'FAILED: {total} fault(s)')
    return 0 if total == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
