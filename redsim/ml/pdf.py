"""PDF projection of a ``CampaignRecord`` (spec 14.8, 17.4; REVIEW_REPORTS-15, -16).

``render_pdf`` typesets the same six-section Markdown ``redsim.ml.reporting``
produces, so the PDF is a third projection of the record and never a
recomputation: every number, fraction, table and caveat is the Markdown's,
converted line by line (headings to four levels, tables, bullets, block quotes,
paragraphs; ``**bold**`` and ```code``` inline) into reportlab platypus
flowables. Whatever the Markdown gains (the Phase B text edit-budget and
detection scorecard tables, the per-modality observation evidence, the nested
LLM probe block) is in the PDF by construction; the tests read it back with pypdf.

Choices recorded by REVIEW_REPORTS-15:

* reportlab (pure Python, no system libraries) rather than weasyprint (pango,
  cairo), xhtml2pdf (a chain of transitive packages) or a headless browser;
* the DejaVu Sans faces (Bitstream Vera licence, see ``pdf_fonts/LICENSE``)
  bundled as Unicode-range subsets under ``redsim/ml/pdf_fonts/`` so ``ε``,
  ``Δ``, ``≥``, ``→`` and ``—`` render; ``REDSIM_PDF_FONT_DIR`` points at a
  directory holding the full faces when an operator prefers them, and the
  matplotlib copy is the last fallback; without any DejaVu face the render
  refuses (``PdfFontsUnavailable``) rather than silently dropping glyphs;
* ``invariant=1`` so identical inputs give byte-identical bytes (fixed document
  id and creation date); the generation stamp is the caller's, the same one
  printed in section 1 of the Markdown.

reportlab is imported inside :func:`render_pdf` only: the API process never
loads it (``tests/test_api_process_has_no_ml.py``).
"""

from __future__ import annotations

import io
import os
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from redsim.ml.reporting import SECTION_HEADINGS, render_markdown
from redsim.ml.schema import CampaignRecord

PDF_MAGIC = b"%PDF-"
PDF_CONTENT_TYPE = "application/pdf"

FONT_DIR_ENV = "REDSIM_PDF_FONT_DIR"
BUNDLED_FONT_DIR = Path(__file__).with_name("pdf_fonts")
FONT_REGULAR = "DejaVuSans"
FONT_BOLD = "DejaVuSans-Bold"
FONT_FILES: dict[str, str] = {FONT_REGULAR: "DejaVuSans.ttf", FONT_BOLD: "DejaVuSans-Bold.ttf"}

#: The six section titles as they appear in the PDF (the Markdown headings without ``## ``).
PDF_SECTION_HEADINGS: tuple[str, ...] = tuple(h.removeprefix("## ") for h in SECTION_HEADINGS)

_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_CODE_RE = re.compile(r"`([^`]+)`")
_CODE_COLOR = "#1f3a5f"

_fonts_registered = False


class PdfFontsUnavailable(RuntimeError):
    """No DejaVu face could be found: the PDF is not rendered with a Latin-1-only font."""


def font_dir() -> Path:
    """The directory holding ``DejaVuSans.ttf`` and ``DejaVuSans-Bold.ttf``.

    Order: ``REDSIM_PDF_FONT_DIR`` (must hold both files), the bundled subsets,
    matplotlib's ``mpl-data/fonts/ttf`` copy. Raises :class:`PdfFontsUnavailable`.
    """
    candidates: list[Path] = []
    override = os.environ.get(FONT_DIR_ENV)
    if override:
        candidates.append(Path(override))
    candidates.append(BUNDLED_FONT_DIR)
    try:
        import matplotlib

        candidates.append(Path(matplotlib.__file__).parent / "mpl-data" / "fonts" / "ttf")
    except Exception:  # noqa: BLE001 - matplotlib is optional here
        pass
    for candidate in candidates:
        if all((candidate / name).is_file() for name in FONT_FILES.values()):
            return candidate
    raise PdfFontsUnavailable(
        "DejaVu Sans faces not found; looked in " + ", ".join(str(c) for c in candidates)
        + f". Set {FONT_DIR_ENV} to a directory holding {sorted(FONT_FILES.values())}."
    )


def register_fonts() -> Path:
    """Register the two DejaVu faces with reportlab once per process; returns the directory used."""
    global _fonts_registered
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    directory = font_dir()
    if _fonts_registered and all(name in pdfmetrics.getRegisteredFontNames() for name in FONT_FILES):
        return directory
    for name, filename in FONT_FILES.items():
        pdfmetrics.registerFont(TTFont(name, str(directory / filename)))
    pdfmetrics.registerFontFamily(FONT_REGULAR, normal=FONT_REGULAR, bold=FONT_BOLD,
                                  italic=FONT_REGULAR, boldItalic=FONT_BOLD)
    _fonts_registered = True
    return directory


# ---------------------------------------------------------------------------
# Markdown line model -> platypus flowables
# ---------------------------------------------------------------------------


def inline(text: str) -> str:
    """Escape a Markdown line for reportlab's paragraph markup and map the two inline forms.

    Everything is escaped first (``&``, ``<``, ``>``), so user strings can never open
    a tag; ``**x**`` becomes bold and ```x``` a coloured span. URL strings stay inert text.
    """
    escaped = escape(text)
    escaped = _BOLD_RE.sub(r"<b>\1</b>", escaped)
    return _CODE_RE.sub(rf'<font color="{_CODE_COLOR}">\1</font>', escaped)


def _split_table_row(line: str) -> list[str]:
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|"):
        body = body[:-1]
    return [cell.strip() for cell in body.split("|")]


def _is_separator_row(cells: Sequence[str]) -> bool:
    return bool(cells) and all(set(cell) <= set("-: ") for cell in cells)


def _column_widths(rows: Sequence[Sequence[str]], available: float) -> list[float]:
    """Widths proportional to the longest cell per column, bounded so no column starves."""
    n_cols = max(len(row) for row in rows)
    # Floor of seven characters so a short header ("N", "Family") never wraps its cells.
    longest = [7.0] * n_cols
    for row in rows:
        for index, cell in enumerate(row):
            longest[index] = max(longest[index], min(float(len(cell)), 40.0))
    total = sum(longest)
    return [available * weight / total for weight in longest]


class _Styles:
    def __init__(self) -> None:
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle

        self.colors = colors
        self.title = ParagraphStyle("title", fontName=FONT_BOLD, fontSize=15, leading=19, spaceAfter=8)
        self.h2 = ParagraphStyle("h2", fontName=FONT_BOLD, fontSize=12, leading=15, spaceBefore=10, spaceAfter=5)
        self.h3 = ParagraphStyle("h3", fontName=FONT_BOLD, fontSize=10, leading=13, spaceBefore=7, spaceAfter=3)
        # The LLM probe fragment's own headings, nested under "LLM probe results" by redsim.ml.reporting.
        self.h4 = ParagraphStyle("h4", fontName=FONT_BOLD, fontSize=9, leading=11.5, spaceBefore=5, spaceAfter=2)
        self.body = ParagraphStyle("body", fontName=FONT_REGULAR, fontSize=8, leading=10.5, spaceAfter=2)
        self.bullet = ParagraphStyle("bullet", parent=self.body, leftIndent=12, bulletIndent=2)
        self.bullet2 = ParagraphStyle("bullet2", parent=self.body, leftIndent=26, bulletIndent=14)
        self.quote = ParagraphStyle("quote", parent=self.body, leftIndent=14, textColor=colors.HexColor("#333333"),
                                    backColor=colors.HexColor("#f3f3f3"))
        self.cell = ParagraphStyle("cell", fontName=FONT_REGULAR, fontSize=6.3, leading=7.6)
        self.cell_head = ParagraphStyle("cell_head", parent=self.cell, fontName=FONT_BOLD)


def _table_flowable(rows: list[list[str]], styles: _Styles, available: float) -> Any:
    from reportlab.platypus import Paragraph, Table, TableStyle

    n_cols = max(len(row) for row in rows)
    padded = [[*row, *([""] * (n_cols - len(row)))] for row in rows]
    data = [
        [Paragraph(inline(cell), styles.cell_head if index == 0 else styles.cell) for cell in row]
        for index, row in enumerate(padded)
    ]
    table = Table(data, colWidths=_column_widths(padded, available), repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, styles.colors.HexColor("#999999")),
        ("BACKGROUND", (0, 0), (-1, 0), styles.colors.HexColor("#e8e8e8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    return table


def flowables_from_markdown(markdown: str, styles: _Styles, available: float) -> list[Any]:
    """Convert the report Markdown, line by line, into platypus flowables."""
    from reportlab.platypus import Paragraph, Spacer

    story: list[Any] = []
    table_rows: list[list[str]] = []

    def flush_table() -> None:
        nonlocal table_rows
        if table_rows:
            story.append(_table_flowable(table_rows, styles, available))
            story.append(Spacer(1, 4))
        table_rows = []

    for raw in markdown.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|") and len(stripped) > 1:
            cells = _split_table_row(stripped)
            if not _is_separator_row(cells):
                table_rows.append(cells)
            continue
        flush_table()
        if not stripped:
            if story and not isinstance(story[-1], Spacer):
                story.append(Spacer(1, 3))
            continue
        if line.startswith("# "):
            story.append(Paragraph(inline(line[2:]), styles.title))
        elif line.startswith("## "):
            story.append(Paragraph(inline(line[3:]), styles.h2))
        elif line.startswith("### "):
            story.append(Paragraph(inline(line[4:]), styles.h3))
        elif line.startswith("#### "):
            story.append(Paragraph(inline(line[5:]), styles.h4))
        elif line.startswith("- "):
            story.append(Paragraph(inline(line[2:]), styles.bullet, bulletText="•"))
        elif line.startswith("  - "):
            story.append(Paragraph(inline(line[4:]), styles.bullet2, bulletText="–"))
        elif line.startswith("> ") or line == ">":
            story.append(Paragraph(inline(line[2:]) or "&nbsp;", styles.quote))
        else:
            story.append(Paragraph(inline(stripped), styles.body))
    flush_table()
    return story


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


def render_pdf(
    record: CampaignRecord,
    *,
    generated_at: datetime | None = None,
    markdown: str | None = None,
) -> bytes:
    """The ``report.pdf`` bytes for ``record``: the Markdown projection typeset with reportlab.

    ``markdown`` lets a caller that already rendered the Markdown for the same
    ``generated_at`` reuse it, so the four formats of one render agree to the
    byte. Deterministic: the same record and stamp give the same bytes.
    """
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.platypus import SimpleDocTemplate

    register_fonts()
    stamp = generated_at if generated_at is not None else datetime.now(UTC)
    text = markdown if markdown is not None else render_markdown(record, generated_at=stamp)
    styles = _Styles()
    page_width, _page_height = landscape(A4)
    margin = 36.0
    available = page_width - 2 * margin

    footer_text = (f"Redsim adversarial-ML campaign report — run {record.run_id} — record schema "
                   f"{record.schema_version} — generated {stamp.isoformat()}")

    def _footer(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont(FONT_REGULAR, 6.5)
        canvas.drawString(margin, 20, footer_text[:180])
        canvas.drawRightString(page_width - margin, 20, f"page {doc.page}")
        canvas.restoreState()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(A4), leftMargin=margin, rightMargin=margin, topMargin=margin,
        bottomMargin=margin, title=f"Redsim ML campaign report — {record.run_id}", author="redsim",
        subject=f"campaign record {record.schema_version}", creator="redsim.ml.pdf", invariant=1,
    )
    doc.build(flowables_from_markdown(text, styles, available), onFirstPage=_footer, onLaterPages=_footer)
    data = buffer.getvalue()
    if not data.startswith(PDF_MAGIC):
        raise RuntimeError("reportlab produced bytes without the %PDF- magic")
    return data


__all__ = [
    "BUNDLED_FONT_DIR",
    "FONT_BOLD",
    "FONT_DIR_ENV",
    "FONT_FILES",
    "FONT_REGULAR",
    "PDF_CONTENT_TYPE",
    "PDF_MAGIC",
    "PDF_SECTION_HEADINGS",
    "PdfFontsUnavailable",
    "flowables_from_markdown",
    "font_dir",
    "inline",
    "register_fonts",
    "render_pdf",
]
