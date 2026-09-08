"""Security headers for report responses (Phase 4 v0.4.0 F14d).

Every HTML report response carries a strict CSP, ``X-Content-Type-Options``
nosniff, ``Referrer-Policy``, and ``Content-Disposition`` so an injected
``<script>…</script>`` payload in finding evidence can never execute
even if the renderer's escaping misses one path.
"""

from __future__ import annotations

REPORT_CSP = (
    "default-src 'none'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src data:; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'none'"
)


def html_report_headers(filename: str | None = None) -> dict[str, str]:
    """Headers attached to a ``text/html`` report response.

    ``Content-Disposition: inline`` is the default — clicking the
    "Open HTML report" link in the UI loads the rendered report in a
    new tab. Pass an explicit ``filename`` to force a download instead.
    """
    headers = {
        "Content-Security-Policy": REPORT_CSP,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
    }
    if filename:
        headers["Content-Disposition"] = (
            f"attachment; filename={filename!r}"
        )
    else:
        headers["Content-Disposition"] = "inline"
    return headers


def non_html_report_headers(filename: str) -> dict[str, str]:
    """Headers for JSON / Markdown / export downloads.

    Same nosniff + Referrer-Policy as HTML; CSP omitted (non-HTML doesn't
    need it). ``Content-Disposition: attachment`` so the browser downloads
    rather than rendering.
    """
    return {
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Disposition": f"attachment; filename={filename!r}",
    }
