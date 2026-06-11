"""Live web OSINT search via the Camoufox anti-detect browser.

Vendored and adapted from c3-e/c3cdao-pipeassist (osc-shared ``osint_browser``).
We use it instead of a Google/SerpAPI search tool: it drives DuckDuckGo's
HTML-only endpoint through Camoufox (a patched, anti-fingerprint Firefox) and
extracts article text with trafilatura — no API key, low detection risk.

Camoufox ships a patched Firefox binary that must be fetched out of band
(``camoufox fetch``), so the dependency is the optional ``osint`` extra. Every
public entry point degrades to a clear, structured error when Camoufox or
trafilatura is not installed, so importing this module is always safe (the
offline test path never launches a browser).

The search tool is classified ``external`` (it reaches third-party sites), so
it clears the human-in-the-loop gate like any other external-effect capability.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, quote_plus, urlparse

logger = logging.getLogger(__name__)

#: Effect class for the OSINT search tool (reaches third-party sites).
OSINT_SEARCH_EFFECT = "external"


class OsintSearchUnavailable(RuntimeError):
    """Raised when the Camoufox browser stack is not importable/installed."""


@dataclass(frozen=True)
class SearchResult:
    title: str
    url: str
    snippet: str


@dataclass(frozen=True)
class ArticleContent:
    title: str
    url: str
    text: str
    extracted_at: str = ""
    word_count: int = 0


def _extract_with_trafilatura(html: str, url: str) -> str | None:
    """High-quality article extraction; ``None`` if trafilatura is absent/fails."""
    try:
        import trafilatura
    except ImportError:
        return None
    try:
        return trafilatura.extract(
            html,
            url=url,
            include_comments=False,
            include_tables=True,
            favor_precision=True,
        )
    except Exception:  # noqa: BLE001 - extraction is best-effort
        logger.debug("trafilatura extraction failed for %s", url, exc_info=True)
        return None


class OSINTBrowser:
    """Async Camoufox session for OSINT search + article extraction.

    Usage::

        async with OSINTBrowser() as browser:
            results = await browser.search("defense tech investment")
            articles = await browser.search_and_extract("...", max_results=3)
    """

    def __init__(self, *, headless: bool = True, block_images: bool = True) -> None:
        self._headless = headless
        self._block_images = block_images
        self._browser: Any = None
        self._cm: Any = None

    async def __aenter__(self) -> OSINTBrowser:
        try:
            from camoufox.async_api import AsyncCamoufox
        except ImportError as exc:  # pragma: no cover - exercised via the wrapper
            raise OsintSearchUnavailable(
                "camoufox is not installed; install the 'osint' extra and run "
                "`camoufox fetch` to enable live OSINT search"
            ) from exc
        self._cm = AsyncCamoufox(headless=self._headless, block_images=self._block_images)
        self._browser = await self._cm.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._cm is not None:
            await self._cm.__aexit__(*args)
        self._browser = None
        self._cm = None

    async def search(self, query: str, *, max_results: int = 10) -> list[SearchResult]:
        """Search DuckDuckGo's HTML endpoint and return structured results."""
        page = await self._browser.new_page()
        try:
            url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            results: list[SearchResult] = []
            for entry in (await page.query_selector_all(".result"))[:max_results]:
                try:
                    title_el = await entry.query_selector(".result__title a, .result__a")
                    snippet_el = await entry.query_selector(".result__snippet")
                    if title_el is None:
                        continue
                    title = (await title_el.inner_text()) or ""
                    href = (await title_el.get_attribute("href")) or ""
                    snippet = (await snippet_el.inner_text()) if snippet_el else ""
                    if not (title and href):
                        continue
                    # DuckDuckGo wraps result links in a redirect (?uddg=<real-url>).
                    if "uddg=" in href:
                        href = parse_qs(urlparse(href).query).get("uddg", [href])[0]
                    results.append(
                        SearchResult(title=title.strip(), url=href, snippet=snippet.strip())
                    )
                except Exception:  # noqa: BLE001 - skip malformed rows
                    logger.debug("skipping result row with missing fields", exc_info=True)
            logger.info("DuckDuckGo search %r: %d results", query, len(results))
            return results
        finally:
            await page.close()

    async def extract_article(self, url: str) -> ArticleContent:
        """Navigate to ``url`` and extract readable article text (capped)."""
        page = await self._browser.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=20000)
            title = await page.title()
            html = await page.content()
            text = _extract_with_trafilatura(html, url)
            if not text:
                for selector in (
                    "article", "main", "[role='main']",
                    ".post-content", ".article-body", "#content",
                ):
                    el = await page.query_selector(selector)
                    if el:
                        text = await el.inner_text()
                        break
            if not text:
                body = await page.query_selector("body")
                if body:
                    text = await body.inner_text()
            text = (text or "").strip()
            return ArticleContent(
                title=title,
                url=url,
                text=text[:5000],
                extracted_at=datetime.now(UTC).isoformat(),
                word_count=len(text.split()),
            )
        except Exception as exc:  # noqa: BLE001 - per-URL failure is non-fatal
            logger.warning("failed to extract article from %s: %s", url, exc)
            return ArticleContent(
                title="", url=url, text=f"[extraction failed: {exc}]",
                extracted_at=datetime.now(UTC).isoformat(),
            )
        finally:
            await page.close()

    async def search_and_extract(
        self, query: str, *, max_results: int = 5,
    ) -> list[ArticleContent]:
        """Search, then extract article text from each top result."""
        results = await self.search(query, max_results=max_results)
        articles: list[ArticleContent] = []
        for result in results:
            article = await self.extract_article(result.url)
            if article.text and not article.text.startswith("[extraction failed"):
                articles.append(article)
        logger.info(
            "search+extract %r: %d/%d articles", query, len(articles), len(results),
        )
        return articles


def camoufox_available() -> bool:
    """True when the Camoufox browser stack can be imported."""
    try:
        import camoufox.async_api  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


async def osint_search_async(query: str, max_results: int = 5) -> dict[str, Any]:
    """Run a live OSINT search and return ``{"query", "rows": [...]}``.

    Raises :class:`OsintSearchUnavailable` if Camoufox is not installed.
    """
    async with OSINTBrowser() as browser:
        articles = await browser.search_and_extract(query, max_results=max_results)
    return {"query": query, "count": len(articles), "rows": [asdict(a) for a in articles]}


def osint_search(query: str, max_results: int = 5) -> dict[str, Any]:
    """Synchronous wrapper around :func:`osint_search_async`.

    Returns a structured error dict (rather than raising) when Camoufox is
    unavailable, so agent toolbelts and callers stay robust offline.
    """
    if not camoufox_available():
        return {
            "query": query,
            "count": 0,
            "rows": [],
            "error": (
                "camoufox not installed; install the 'osint' extra and run "
                "`camoufox fetch` to enable live OSINT search"
            ),
        }
    try:
        return asyncio.run(osint_search_async(query, max_results=max_results))
    except OsintSearchUnavailable as exc:
        return {"query": query, "count": 0, "rows": [], "error": str(exc)}


def build_osint_search_tool() -> Any | None:
    """Return a CAI ``@function_tool`` wrapping :func:`osint_search`, or ``None``.

    ``None`` when the CAI SDK isn't importable (offline), so agent composition
    can simply skip it. The returned tool is what OSINT/recon agents add to
    their toolbelt in place of a Google search tool.
    """
    try:
        from cai.sdk.agents import function_tool
    except Exception:  # noqa: BLE001 - CAI not importable
        return None

    @function_tool
    def search_web_osint(query: str, max_results: int = 5) -> str:
        """Search the public web (DuckDuckGo via an anti-detect browser) and
        return extracted article text. Use short, specific English queries."""
        import json

        return json.dumps(osint_search(query, max_results=max_results), indent=2)

    return search_web_osint
