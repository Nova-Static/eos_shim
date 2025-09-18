#!/usr/bin/env python3
"""
Scans ./pages and generates ./routes.generated.js for Vue Router (ESM, no bundler).

Conventions:
- pages/index.js           -> "/"
- pages/about.js           -> "/about"
- pages/blog/index.js      -> "/blog"
- pages/blog/[slug].js     -> "/blog/:slug"
- pages/docs/[...rest].js  -> "/docs/:rest(.*)"
- pages/docs/[[...opt]].js -> "/docs/:opt(.*)?"

Usage:
    python3 generate_routes.py
    python3 generate_routes.py --pages src/pages --out src/routes.generated.js
"""

from __future__ import annotations
import argparse
from pathlib import Path
from datetime import datetime
import re
import sys

DYNAMIC_SEG_RE   = re.compile(r'^\[(.+)\]$')            # [id] -> :id
CATCH_ALL_RE     = re.compile(r'^\[\.\.\.(.+)\]$')      # [...rest] -> :rest(.*)
OPT_CATCH_ALL_RE = re.compile(r'^\[\[(\.\.\.)?(.+)\]\]$')  # [[...rest]] -> :rest(.*)?

def seg_to_route(seg: str) -> str:
    """Convert a single file/folder segment to a route segment."""
    if CATCH_ALL_RE.match(seg):
        name = CATCH_ALL_RE.match(seg).group(1)
        return f":{name}(.*)"
    if OPT_CATCH_ALL_RE.match(seg):
        name = OPT_CATCH_ALL_RE.match(seg).group(2)
        return f":{name}(.*)?"
    if DYNAMIC_SEG_RE.match(seg):
        name = DYNAMIC_SEG_RE.match(seg).group(1)
        return f":{name}"
    if seg == "index":
        return ""
    return seg

def file_to_route_path(rel_no_ext: Path) -> str:
    """Turn 'blog/[slug]' into '/blog/:slug' etc."""
    parts = [p for p in (seg_to_route(s) for s in rel_no_ext.as_posix().split('/')) if p != ""]
    path = "/" + "/".join(parts)
    return "/" if path == "" else path

def sort_key(path: str) -> tuple:
    """Specificity sort: static first, fewer dynamics, deeper paths first, then alpha."""
    catch_all = 1 if "(.*" in path else 0
    dyn = path.count(":")
    depth = len([p for p in path.split("/") if p])
    return (catch_all, dyn, -depth, path)

def ensure_rel_prefix(p: str) -> str:
    # Ensure the import path starts with './' or '../' (never bare or absolute)
    if p.startswith(("./", "../")):
        return p
    return "./" + p

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pages", default="pages", help="Directory to scan for page modules")
    parser.add_argument("--out", default="routes.generated.js", help="Output JS file path")
    parser.add_argument("--ext", default=".js", help="Page file extension to include (default: .js)")
    args = parser.parse_args()

    script_dir = Path.cwd()
    pages_dir = (script_dir / args.pages).resolve()
    out_file  = (script_dir / args.out).resolve()

    if not pages_dir.exists():
        print(f"[ERROR] Pages directory not found: {pages_dir}", file=sys.stderr)
        sys.exit(1)

    # Collect page files
    files = sorted([p for p in pages_dir.rglob(f"*{args.ext}") if p.is_file()])

    entries = []
    for f in files:
        rel_to_pages = f.relative_to(pages_dir)
        rel_no_ext = rel_to_pages.with_suffix("")  # drop .js
        route_path = file_to_route_path(rel_no_ext)

        # Compute import path relative to the output file location
        rel_from_out = f.relative_to(out_file.parent).as_posix() if pages_dir in f.parents else \
                       Path.relpath(f, out_file.parent).replace("\\", "/")
        import_path = ensure_rel_prefix(rel_from_out)

        # Count dynamics/catch-all for sorting later
        entries.append({
            "path": route_path,
            "import_path": import_path,
        })

    # Sort for routing specificity
    entries.sort(key=lambda e: sort_key(e["path"]))

    # Deduplicate identical route paths (keep the first, warn on conflicts)
    seen = set()
    deduped = []
    for e in entries:
        if e["path"] in seen:
            print(f"[WARN] Duplicate route path ignored: {e['path']}", file=sys.stderr)
            continue
        seen.add(e["path"])
        deduped.append(e)

    header = (
        "// AUTO-GENERATED — DO NOT EDIT\n"
        f"// Generated on {datetime.utcnow().isoformat(timespec='seconds')}Z\n"
        f"// Source directory: {pages_dir.as_posix()}\n\n"
    )

    lines = [header, "export const routes = [\n"]
    for e in deduped:
        lines.append(f"  {{ path: {e['path']!r}, component: () => import({e['import_path']!r}) }},\n")
    lines.append("];\n")

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("".join(lines), encoding="utf-8")

    print(f"[OK] Wrote {out_file.relative_to(script_dir)} with {len(deduped)} routes.")

if __name__ == "__main__":
    main()
