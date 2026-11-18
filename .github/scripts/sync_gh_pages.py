#!/usr/bin/env python3
"""Build static GitHub Pages site for nxtflow from docs/ and README.md."""

from __future__ import annotations

import html
import re
import shutil
import sys
import tomllib
from pathlib import Path

PAGES = [
    ("docs/index.md", "index.html", "Overview"),
    ("docs/architecture.md", "architecture.html", "Architecture"),
    ("docs/standalone-vs-integrated.md", "standalone-vs-integrated.html", "Deployment Modes"),
    ("charts/nxtflow/README.md", "helm-chart.html", "Helm Chart"),
    ("docs/exporters.md", "exporters.html", "Exporter Guides"),
    ("docs/ai-integration.md", "ai-integration.html", "CLI, MCP & AI Skill"),
    ("CHANGELOG.md", "changelog.html", "Changelog"),
]

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title} — nxtflow</title>
  <meta name="description" content="AI-ready multi-site NetFlow v5/v9, IPFIX, and sFlow telemetry platform for Kubernetes and Loki." />
  <meta property="og:title" content="{title} — nxtflow" />
  <meta property="og:image" content="assets/nxtflow-logo.png" />
  <link rel="icon" type="image/png" href="assets/nxtflow-icon.png" />
  <style>
    :root {{
      --bg: #0b101b;
      --surface: #111827;
      --border: #1e293b;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --accent2: #818cf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.65;
    }}
    header {{
      border-bottom: 1px solid var(--border);
      background: rgba(17, 24, 39, 0.92);
      padding: 0.85rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      color: #fff;
      text-decoration: none;
      font-weight: 700;
      font-size: 1.15rem;
    }}
    .brand img {{ height: 32px; width: 32px; border-radius: 8px; }}
    nav {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
    nav a {{
      color: var(--muted);
      text-decoration: none;
      font-size: 0.92rem;
      font-weight: 500;
    }}
    nav a:hover, nav a.active {{ color: var(--accent); }}
    .layout {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 2rem 1.5rem 4rem;
      display: grid;
      grid-template-columns: 1fr 240px;
      gap: 2.5rem;
    }}
    @media (max-width: 900px) {{
      .layout {{ grid-template-columns: 1fr; }}
      aside {{ order: -1; }}
    }}
    main {{ min-width: 0; }}
    aside {{
      position: sticky;
      top: 1.5rem;
      align-self: start;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1rem 1.15rem;
      font-size: 0.88rem;
    }}
    aside h3 {{ margin-top: 0; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }}
    aside ul {{ list-style: none; padding-left: 0.75rem; margin: 0.35rem 0; }}
    aside > .toc > ul {{ padding-left: 0; }}
    aside a {{ color: var(--muted); text-decoration: none; }}
    aside a:hover {{ color: var(--accent); }}
    h1, h2, h3 {{ color: #f8fafc; line-height: 1.3; }}
    a {{ color: var(--accent); }}
    pre, code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      background: var(--surface);
      border-radius: 6px;
    }}
    code {{ padding: 0.15rem 0.4rem; font-size: 0.9em; }}
    pre {{
      padding: 1rem;
      overflow-x: auto;
      border: 1px solid var(--border);
    }}
    pre code {{ padding: 0; background: none; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 1.25rem 0;
      font-size: 0.92rem;
    }}
    th, td {{
      border: 1px solid var(--border);
      padding: 0.6rem 0.8rem;
      text-align: left;
    }}
    th {{ background: var(--surface); color: #f8fafc; }}
    img {{ max-width: 100%; height: auto; }}
  </style>
</head>
<body>
  <header>
    <a class="brand" href="index.html">
      <img src="assets/nxtflow-icon.png" alt="nxtflow icon" />
      <span>nxtflow <small style="color: var(--muted); font-weight: 500;">v{version}</small></span>
    </a>
    <nav>{nav_links}</nav>
  </header>
  <div class="layout">
    <main>{body_html}</main>
    <aside>
      <h3>On This Page</h3>
      {toc_html}
    </aside>
  </div>
</body>
</html>
"""


def rewrite_links(md_text: str, src_rel: str = "") -> str:
    """Rewrite relative docs/ and ../ links (including #anchors) for the static _site output."""
    md_text = re.sub(
        r"\((?:\.\./|docs/)?(?:\.\./)?charts/nxtflow/README\.md(#[^)]*)?\)",
        lambda m: f"(helm-chart.html{m.group(1) or ''})",
        md_text,
    )
    if src_rel == "charts/nxtflow/README.md":
        md_text = re.sub(
            r"\((values\.yaml|values\.schema\.json)(#[^)]*)?\)",
            lambda m: f"(https://github.com/nertwork/nxtflow/blob/main/charts/nxtflow/{m.group(1)}{m.group(2) or ''})",
            md_text,
        )
    for md_src, html_dst, _ in PAGES:
        if md_src == "charts/nxtflow/README.md":
            continue
        md_name = Path(md_src).name
        md_text = re.sub(
            rf"\((?:\.\./|docs/)?{re.escape(md_name)}(#[^)]*)?\)",
            lambda m, dst=html_dst: f"({dst}{m.group(1) or ''})",
            md_text,
        )
    return re.sub(
        r"\(\.\./(?!assets/)([^)]+)\)",
        r"(https://github.com/nertwork/nxtflow/blob/main/\1)",
        md_text,
    )


def get_version(repo_root: Path) -> str:
    pyproject = repo_root / "pyproject.toml"
    if pyproject.is_file():
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        return str(data.get("project", {}).get("version", "0.1.0"))
    return "0.1.0"


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: sync_gh_pages.py <output-dir>", file=sys.stderr)
        return 1

    repo_root = Path(__file__).resolve().parent.parent.parent
    out_dir = Path(sys.argv[1]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    version = get_version(repo_root)

    # Copy real assets to _site/assets/
    src_assets = repo_root / "docs" / "assets"
    if not src_assets.is_dir():
        src_assets = repo_root / "assets"
    if src_assets.is_dir():
        dst_assets = out_dir / "assets"
        dst_assets.mkdir(parents=True, exist_ok=True)
        for item in src_assets.iterdir():
            if item.is_file():
                shutil.copy2(item, dst_assets / item.name)

    # Copy raw markdown files for direct linking too
    for src_rel, dest_html, label in PAGES:
        src_path = repo_root / src_rel
        if not src_path.is_file():
            continue
        import markdown

        md_text = rewrite_links(src_path.read_text(encoding="utf-8"), src_rel=src_rel)

        md = markdown.Markdown(extensions=["toc", "fenced_code", "tables"])
        body_html = md.convert(md_text)
        toc_html = md.toc

        nav_links = "\n      ".join(
            [
                f'<a href="{h}" class="{"active" if h == dest_html else ""}">{html.escape(lbl)}</a>'
                for _, h, lbl in PAGES
            ]
            + ['<a href="https://github.com/nertwork/nxtflow" target="_blank" rel="noopener">GitHub</a>']
        )

        rendered = HTML_TEMPLATE.format(
            title=html.escape(label),
            version=html.escape(version),
            nav_links=nav_links,
            body_html=body_html,
            toc_html=toc_html,
        )
        (out_dir / dest_html).write_text(rendered, encoding="utf-8")

    base_url = "https://nertwork.github.io/nxtflow"
    url_entries = "\n".join(
        f"  <url><loc>{base_url}/{'' if h == 'index.html' else h}</loc></url>"
        for _, h, _ in PAGES
    )
    (out_dir / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{url_entries}\n"
        "</urlset>\n",
        encoding="utf-8",
    )
    (out_dir / "robots.txt").write_text(
        f"User-agent: *\nAllow: /\nSitemap: {base_url}/sitemap.xml\n",
        encoding="utf-8",
    )
    (out_dir / "404.html").write_text(
        HTML_TEMPLATE.format(
            title="Page Not Found",
            version=html.escape(version),
            nav_links="\n      ".join(
                f'<a href="{h}">{html.escape(lbl)}</a>' for _, h, lbl in PAGES
            ),
            body_html="<h1>404 — Page Not Found</h1><p>Return to the <a href=\"index.html\">nxtflow documentation home</a>.</p>",
            toc_html="",
        ),
        encoding="utf-8",
    )

    # Disable Jekyll processing
    (out_dir / ".nojekyll").write_text("", encoding="utf-8")
    print(f"Built nxtflow GitHub Pages site (v{version}) at {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
