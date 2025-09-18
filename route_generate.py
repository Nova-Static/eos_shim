# routes_codegen.py
from __future__ import annotations
import os
import re
import json
from pathlib import Path
from datetime import datetime

# [id] -> :id
DYNAMIC_SEG_RE   = re.compile(r'^\[(.+)\]$')
# [...rest] -> :rest(.*)
CATCH_ALL_RE     = re.compile(r'^\[\.\.\.(.+)\]$')
# [[...rest]] -> :rest(.*)?
OPT_CATCH_ALL_RE = re.compile(r'^\[\[(\.\.\.)?(.+)\]\]$')

def _seg_to_route(seg: str) -> str:
    m = CATCH_ALL_RE.match(seg)
    if m: return f":{m.group(1)}(.*)"
    m = OPT_CATCH_ALL_RE.match(seg)
    if m: return f":{m.group(2)}(.*)?"
    m = DYNAMIC_SEG_RE.match(seg)
    if m: return f":{m.group(1)}"
    if seg == "index": return ""
    return seg

def _file_to_route_path(rel_no_ext: Path) -> str:
    parts = [p for p in (_seg_to_route(s) for s in rel_no_ext.as_posix().split('/')) if p != ""]
    path = "/" + "/".join(parts)
    return "/" if path == "" else path

def _sort_key(route_path: str):
    catch_all = 1 if "(.*" in route_path else 0
    dyn = route_path.count(":")
    depth = len([p for p in route_path.split("/") if p])
    return (catch_all, dyn, -depth, route_path)

def _ensure_rel_prefix(p: str) -> str:
    if p.startswith(("./", "../")): return p
    return "./" + p

def generate_routes(
    pages: str = "pages",
    out: str = "routes.generated.js",
    ext: str = ".js",
    *,
    inject_html: bool = True,
    html_ext: str = ".html",
) -> int:
    """
    Scan `pages/` for *.js, write a Vue Router manifest to `routes.generated.js`.
    If `inject_html` is True and a sibling *.html exists, its contents are embedded and
    used to override the component's `template` when the route is lazy-loaded.
    Returns the number of routes written.
    """
    cwd = Path.cwd()
    pages_dir = (cwd / pages).resolve()
    out_file  = (cwd / out).resolve()

    if not pages_dir.exists():
        raise FileNotFoundError(f"Pages directory not found: {pages_dir}")

    files = sorted(p for p in pages_dir.rglob(f"*{ext}") if p.is_file())

    entries = []
    templates_map: dict[str, str] = {}

    for f in files:
        rel_to_pages = f.relative_to(pages_dir)
        rel_no_ext = rel_to_pages.with_suffix("")
        route_path = _file_to_route_path(rel_no_ext)

        # Import path (relative to the output file dir)
        rel_from_out = os.path.relpath(str(f), start=str(out_file.parent)).replace("\\", "/")
        import_path = _ensure_rel_prefix(rel_from_out)

        # Optional adjacent HTML
        if inject_html:
            html_path = f.with_suffix(html_ext)
            if html_path.exists():
                html_text = html_path.read_text(encoding="utf-8")
                # Store raw text; will be JSON-encoded safely in the generated file
                templates_map[import_path] = html_text

        entries.append({"path": route_path, "import_path": import_path})

    # Sort for specificity
    entries.sort(key=lambda e: _sort_key(e["path"]))

    # Deduplicate identical route paths
    seen, deduped = set(), []
    for e in entries:
        if e["path"] in seen:
            continue
        seen.add(e["path"])
        deduped.append(e)

    header = (
        "// AUTO-GENERATED — DO NOT EDIT\n"
        f"// Generated on {datetime.utcnow().isoformat(timespec='seconds')}Z\n"
        f"// Source directory: {pages_dir.as_posix()}\n\n"
    )

    # Helper that merges the baked-in template (if present)
    helper = (
        "const __ROUTES_TEMPLATES__ = "
        + json.dumps(templates_map, ensure_ascii=False)
        + ";\n"
        "function __withTemplate__(mod, importPath) {\n"
        "  const tpl = __ROUTES_TEMPLATES__[importPath];\n"
        "  const base = (mod && 'default' in mod) ? mod.default : (mod || {});\n"
        "  if (!tpl) return base;\n"
        "  if (base && typeof base === 'object') return { ...base, template: tpl };\n"
        "  return { template: tpl };\n"
        "}\n\n"
    )

    lines = [header, helper, "export const routes = [\n"]
    for e in deduped:
        ip = e['import_path']
        lines.append(
            "  { path: "
            + repr(e['path'])
            + f", component: () => import({ip!r}).then(m => __withTemplate__(m, {ip!r})) },\n"
        )
    lines.append("];\n")

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("".join(lines), encoding="utf-8")
    return len(deduped)
