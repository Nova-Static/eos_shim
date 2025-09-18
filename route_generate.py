from __future__ import annotations
import os
import re
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

def generate_routes(pages: str = "pages",
                    out: str = "routes.generated.js",
                    ext: str = ".js") -> int:
    """
    Scan `pages/` and write a Vue Router ESM manifest to `routes.generated.js`.
    Returns the number of routes written.
    """
    cwd = Path.cwd()
    pages_dir = (cwd / pages).resolve()
    out_file  = (cwd / out).resolve()

    if not pages_dir.exists():
        raise FileNotFoundError(f"Pages directory not found: {pages_dir}")

    files = sorted(p for p in pages_dir.rglob(f"*{ext}") if p.is_file())

    entries = []
    for f in files:
        rel_to_pages = f.relative_to(pages_dir)
        rel_no_ext = rel_to_pages.with_suffix("")
        route_path = _file_to_route_path(rel_no_ext)

        rel_from_out = os.path.relpath(str(f), start=str(out_file.parent)).replace("\\", "/")
        import_path = _ensure_rel_prefix(rel_from_out)

        entries.append({"path": route_path, "import_path": import_path})

    entries.sort(key=lambda e: _sort_key(e["path"]))

    seen, deduped = set(), []
    for e in entries:
        if e["path"] in seen:
            # Duplicate route path; ignore later ones
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
    return len(deduped)
