"""Template-free, XSS-safe Markdown -> HTML rendering (inherited from IntelliBridge/aegis report.py).

The report section builders for redsim runs are added per the design spec
(section 2.1 / 6). Every interpolation must go through html_escape().
"""
from __future__ import annotations

import re

def html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;"))


def render_inline_markdown(s: str) -> str:
    s = html_escape(s)
    # bold **x**
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    # inline code `x`
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s


def _md_to_html_min(md: str) -> str:
    """Minimal Markdown → HTML so we don't introduce a heavy dependency.

    Handles headings, paragraphs, code fences, inline backticks, tables, and
    horizontal rules — enough for the report shape we generate. Not a general
    Markdown engine.
    """
    out: list[str] = []
    in_code = False
    code_buf: list[str] = []
    in_table = False
    table_rows: list[list[str]] = []

    def flush_table() -> None:
        nonlocal in_table, table_rows
        if not table_rows:
            in_table = False
            return
        out.append("<table>")
        for i, row in enumerate(table_rows):
            cells = [c.strip() for c in row]
            tag = "th" if i == 0 else "td"
            out.append("<tr>" + "".join(f"<{tag}>{html_escape(c)}</{tag}>" for c in cells) + "</tr>")
        out.append("</table>")
        table_rows = []
        in_table = False

    for raw in md.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            if in_code:
                out.append("<pre><code>" + html_escape("\n".join(code_buf)) + "</code></pre>")
                code_buf = []
                in_code = False
            else:
                if in_table:
                    flush_table()
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue
        if line.startswith("|") and line.endswith("|"):
            if not in_table:
                in_table = True
                table_rows = []
            cells = line.strip("|").split("|")
            # skip the markdown separator row like |---|---|
            if all(set(c.strip()) <= set("-:") for c in cells):
                continue
            table_rows.append(cells)
            continue
        elif in_table:
            flush_table()

        if line.startswith("# "):
            out.append(f"<h1>{render_inline_markdown(line[2:])}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{render_inline_markdown(line[3:])}</h2>")
        elif line.startswith("### "):
            out.append(f"<h3>{render_inline_markdown(line[4:])}</h3>")
        elif line.startswith("#### "):
            out.append(f"<h4>{render_inline_markdown(line[5:])}</h4>")
        elif line.strip() == "---":
            out.append("<hr/>")
        elif line.strip() == "":
            out.append("")
        else:
            out.append(f"<p>{render_inline_markdown(line)}</p>")
    if in_table:
        flush_table()
    if in_code:
        out.append("<pre><code>" + "\n".join(code_buf) + "</code></pre>")
    return "\n".join(out)


