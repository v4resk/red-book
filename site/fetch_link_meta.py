#!/usr/bin/env python3
"""Build the external-link metadata cache used to render rich resource cards.

Fetches each distinct external URL once for its <title>, and each distinct
domain once for its favicon, then writes:

    link-meta.json             url -> {title, domain, icon}
    public/assets/favicons/    the downloaded icons

Both are committed, and the <Card> attributes in content/docs are rewritten
from the cache, so `next build` never touches the network and stays
deterministic and offline.

    npm run links          fetch URLs not yet cached, then rewrite the cards
    npm run links:apply    rewrite cards from the cache only (no network)
    npm run links:refresh  re-fetch everything

Incremental by default: only URLs absent from the cache are fetched, and the
cache is checkpointed every 25 so an interrupted run resumes.
"""
import json, os, re, sys, urllib.parse, urllib.request, concurrent.futures, socket

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.join(HERE, 'content', 'docs')
CACHE = os.path.join(HERE, 'link-meta.json')
ICONS = os.path.join(HERE, 'public', 'assets', 'favicons')
UA = 'Mozilla/5.0 (compatible; red-book-docs-build/1.0; +https://github.com/v4resk/red-book)'
TIMEOUT = 8
socket.setdefaulttimeout(TIMEOUT)


def get(url, limit=200_000):
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': '*/*'})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read(limit), r.headers.get('Content-Type', ''), r.geturl()


def title_of(url):
    try:
        body, ctype, final = get(url)
    except Exception:
        return None, None
    if 'html' not in ctype.lower():
        return None, None
    html = body.decode('utf-8', 'replace')
    m = (re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)', html, re.I)
         or re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S))
    if not m:
        return None, html
    t = re.sub(r'\s+', ' ', m.group(1)).strip()
    t = re.sub(r'&amp;', '&', t)
    t = re.sub(r'&#(\d+);', lambda x: chr(int(x.group(1))), t)
    t = re.sub(r'&[a-z]+;', '', t)
    return (t[:110] or None), html


def favicon_for(domain, html):
    """Prefer the page's declared icon, else /favicon.ico."""
    cands = []
    if html:
        for m in re.finditer(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]*>', html, re.I):
            h = re.search(r'href=["\']([^"\']+)', m.group(0), re.I)
            if h:
                cands.append(urllib.parse.urljoin(f'https://{domain}/', h.group(1)))
    cands.append(f'https://{domain}/favicon.ico')
    for c in cands:
        try:
            data, ctype, _ = get(c, 300_000)
        except Exception:
            continue
        if not data or len(data) < 40:
            continue
        ext = ('svg' if 'svg' in ctype or c.endswith('.svg')
               else 'png' if 'png' in ctype or c.endswith('.png')
               else 'ico')
        fn = re.sub(r'[^a-z0-9.-]', '_', domain.lower()) + '.' + ext
        os.makedirs(ICONS, exist_ok=True)
        with open(os.path.join(ICONS, fn), 'wb') as f:
            f.write(data)
        return fn
    return None


def urls_in_content():
    out = set()
    for root, _, files in os.walk(DOCS):
        for fn in files:
            if fn.endswith('.mdx'):
                txt = open(os.path.join(root, fn), encoding='utf-8', errors='replace').read()
                out |= set(re.findall(r'<Card href="(https?://[^"]+)"', txt))
    return sorted(out)


def apply_to_cards():
    """Rewrite <Card> attributes in the MDX from the cache.

    Post-migration the MDX is the source of truth, so this is what actually
    puts new titles/favicons on the page -- the fetcher alone only fills the
    cache.
    """
    cache = json.load(open(CACHE)) if os.path.exists(CACHE) else {}
    changed = cards = 0
    for root, _, files in os.walk(DOCS):
        for fn in files:
            if not fn.endswith('.mdx'):
                continue
            p = os.path.join(root, fn)
            txt = orig = open(p, encoding='utf-8', errors='replace').read()

            def one(m):
                nonlocal cards
                url = m.group(1)
                meta = cache.get(url) or {}
                domain = meta.get('domain') or re.sub(r'^https?://([^/]+).*', r'\1', url)
                title = meta.get('title') or domain
                cards += 1
                attrs = ['href="%s"' % url, 'title=%s' % json.dumps(title),
                         'description=%s' % json.dumps(domain)]
                if meta.get('icon'):
                    attrs.append('icon="/assets/favicons/%s"' % meta['icon'])
                return '<ResourceCard %s />' % ' '.join(attrs)

            txt = re.sub(r'(?m)^<(?:Card|ResourceCard) href="(https?://[^"]+)".*$', one, txt)
            if txt != orig:
                open(p, 'w', encoding='utf-8').write(txt)
                changed += 1
    print(f"applied cache to {cards} cards across {changed} changed file(s)")


def main():
    refresh = '--refresh' in sys.argv
    cache = {} if refresh else (json.load(open(CACHE)) if os.path.exists(CACHE) else {})
    urls = urls_in_content()
    todo = [u for u in urls if u not in cache]
    print(f"{len(urls)} distinct URLs, {len(todo)} to fetch, {len(cache)} cached")

    domain_icon, html_by_domain = {}, {}
    for fn in (os.listdir(ICONS) if os.path.isdir(ICONS) else []):
        domain_icon[fn.rsplit('.', 1)[0]] = fn

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(title_of, u): u for u in todo}
        for fut in concurrent.futures.as_completed(futs):
            u = futs[fut]
            done += 1
            try:
                title, html = fut.result()
            except Exception:
                title, html = None, None
            dom = urllib.parse.urlparse(u).netloc
            cache[u] = {'title': title, 'domain': dom}
            if html and dom not in html_by_domain:
                html_by_domain[dom] = html
            if done % 25 == 0:
                # checkpoint: an interrupted run resumes instead of starting over
                json.dump(cache, open(CACHE, 'w'), indent=1, sort_keys=True)
                print(f"  …{done}/{len(todo)} (checkpointed)", flush=True)

    doms = sorted({v['domain'] for v in cache.values() if v.get('domain')})
    need = [d for d in doms if re.sub(r'[^a-z0-9.-]', '_', d.lower()) not in domain_icon]
    print(f"{len(doms)} domains, {len(need)} favicons to fetch")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(favicon_for, d, html_by_domain.get(d)): d for d in need}
        for fut in concurrent.futures.as_completed(futs):
            d = futs[fut]
            try:
                fn = fut.result()
            except Exception:
                fn = None
            if fn:
                domain_icon[re.sub(r'[^a-z0-9.-]', '_', d.lower())] = fn

    for u, v in cache.items():
        key = re.sub(r'[^a-z0-9.-]', '_', (v.get('domain') or '').lower())
        v['icon'] = domain_icon.get(key)

    json.dump(cache, open(CACHE, 'w'), indent=1, sort_keys=True)
    got_t = sum(1 for v in cache.values() if v.get('title'))
    got_i = sum(1 for v in cache.values() if v.get('icon'))
    print(f"wrote {CACHE}: {len(cache)} urls, {got_t} titles, {got_i} with favicon")
    apply_to_cards()


if __name__ == '__main__':
    if '--apply-only' in sys.argv:
        apply_to_cards()      # no network: just re-render cards from the cache
    else:
        main()
