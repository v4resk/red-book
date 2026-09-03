#!/usr/bin/env python3
"""Notify IndexNow (Bing, Yandex, DuckDuckGo, ...) of the Red-Book pages that
changed in a push, so they re-index in minutes instead of on the next crawl.

Runs in the deploy job AFTER the rsync, so the URLs are already live when the
engines fetch them. Submits only the pages that changed in the push (IndexNow
discourages resubmitting the whole set). Never fails the deploy: any error is
printed and swallowed.

Env:
  INDEXNOW_KEY  the (public) IndexNow key, also hosted at /<key>.txt
  BEFORE / AFTER  git shas bounding the push (github.event.before / github.sha)
  INDEXNOW_DRY_RUN  if set, print the URLs but do not POST
"""
import os, sys, json, subprocess, urllib.request, urllib.error

KEY = os.environ.get("INDEXNOW_KEY", "").strip()
if not KEY:
    print("INDEXNOW_KEY not set; skipping IndexNow.")
    sys.exit(0)

BASE = "https://infiltr8.io/redbook"
before = os.environ.get("BEFORE", "").strip()
after = os.environ.get("AFTER", "HEAD").strip() or "HEAD"


def changed_urls():
    # A zero/empty BEFORE (first push of a branch) has no usable range; fall
    # back to the single most recent commit.
    rng = [before, after] if before and set(before) != {"0"} else [f"{after}~1", after]
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", *rng, "--", "site/content/docs"],
            capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        print("git diff failed:", e.stderr.strip())
        return []
    urls = set()
    for p in out.splitlines():
        if not (p.startswith("site/content/docs/") and p.endswith(".mdx")):
            continue
        route = p[len("site/content/docs/"):-len(".mdx")]
        if route == "index":
            route = ""
        elif route.endswith("/index"):
            route = route[:-len("/index")]
        urls.add(f"{BASE}/{route}".rstrip("/") + "/")
    return sorted(urls)


urls = changed_urls()
if not urls:
    print("No Red-Book content changed; nothing to submit.")
    sys.exit(0)

print(f"Submitting {len(urls)} URL(s) to IndexNow:")
print("\n".join(urls))

if os.environ.get("INDEXNOW_DRY_RUN"):
    print("(dry run: not posting)")
    sys.exit(0)

body = json.dumps({
    "host": "infiltr8.io",
    "key": KEY,
    "keyLocation": f"https://infiltr8.io/{KEY}.txt",
    "urlList": urls,
}).encode()
req = urllib.request.Request(
    "https://api.indexnow.org/indexnow", data=body,
    headers={"Content-Type": "application/json; charset=utf-8"},
)
try:
    with urllib.request.urlopen(req, timeout=20) as resp:
        print("IndexNow HTTP", resp.status)
except urllib.error.HTTPError as e:
    print("IndexNow HTTP", e.code, e.read().decode()[:200])
except Exception as e:  # network etc. — never fail the deploy
    print("IndexNow request failed:", e)
