"""Tests for the Camoufox-backed OSINT search tool.

No real browser is launched: the Camoufox page/browser objects are faked, so
these run in the offline unit path. We cover the DuckDuckGo result parsing
(incl. the ``uddg=`` redirect unwrap), article extraction fallbacks, the
sync wrapper's graceful degradation when Camoufox is absent, and the CAI
function-tool builder.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from aegis.tools import osint_search as osint


class _FakeElement:
    def __init__(self, text="", attrs=None):
        self._text = text
        self._attrs = attrs or {}

    async def inner_text(self):
        return self._text

    async def get_attribute(self, name):
        return self._attrs.get(name)


class _FakeResultRow:
    def __init__(self, title, href, snippet):
        self._title = _FakeElement(title, {"href": href})
        self._snippet = _FakeElement(snippet)

    async def query_selector(self, selector):
        if "title" in selector or "result__a" in selector:
            return self._title
        if "snippet" in selector:
            return self._snippet
        return None


class _FakePage:
    def __init__(self, rows, *, html="", title="A Title", body_text="body text"):
        self._rows = rows
        self._html = html
        self._title = title
        self._body_text = body_text
        self.closed = False

    async def goto(self, url, **kwargs):
        return None

    async def query_selector_all(self, selector):
        return self._rows

    async def query_selector(self, selector):
        if selector == "body":
            return _FakeElement(self._body_text)
        return None

    async def content(self):
        return self._html

    async def title(self):
        return self._title

    async def close(self):
        self.closed = True


class _FakeBrowser:
    def __init__(self, page):
        self._page = page

    async def new_page(self):
        return self._page


def _browser_with(page):
    """An OSINTBrowser whose __aenter__ yields a fake browser (no Camoufox)."""
    b = osint.OSINTBrowser()
    b._browser = _FakeBrowser(page)
    return b


class TestSearchParsing(unittest.TestCase):
    def test_parses_results_and_unwraps_uddg_redirect(self):
        rows = [
            _FakeResultRow(
                "Aether Defense lands DoD contract",
                "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fnews&rut=x",
                "A snippet about the contract.",
            ),
            _FakeResultRow("Direct link", "https://direct.example/article", "snip2"),
        ]
        page = _FakePage(rows)
        results = asyncio.run(_browser_with(page).search("aether defense", max_results=5))
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].url, "https://example.com/news")
        self.assertEqual(results[1].url, "https://direct.example/article")
        self.assertTrue(page.closed)

    def test_skips_rows_missing_title_or_href(self):
        rows = [_FakeResultRow("", "", ""), _FakeResultRow("ok", "https://x.example", "s")]
        results = asyncio.run(_browser_with(_FakePage(rows)).search("q"))
        self.assertEqual(len(results), 1)


class TestArticleExtraction(unittest.TestCase):
    def test_extract_falls_back_to_body_when_no_trafilatura(self):
        page = _FakePage([], html="<html></html>", title="T", body_text="full body content")
        with mock.patch.object(osint, "_extract_with_trafilatura", return_value=None):
            article = asyncio.run(_browser_with(page).extract_article("https://x.example"))
        self.assertEqual(article.title, "T")
        self.assertIn("full body", article.text)
        self.assertGreater(article.word_count, 0)

    def test_extract_prefers_trafilatura(self):
        page = _FakePage([], html="<html>x</html>")
        with mock.patch.object(osint, "_extract_with_trafilatura", return_value="clean text"):
            article = asyncio.run(_browser_with(page).extract_article("https://x.example"))
        self.assertEqual(article.text, "clean text")

    def test_search_and_extract_drops_failed_extractions(self):
        rows = [_FakeResultRow("t", "https://ok.example", "s")]
        page = _FakePage(rows, html="<html>x</html>")
        with mock.patch.object(osint, "_extract_with_trafilatura", return_value="good"):
            arts = asyncio.run(_browser_with(page).search_and_extract("q", max_results=1))
        self.assertEqual(len(arts), 1)
        self.assertEqual(arts[0].text, "good")


class TestSyncWrapper(unittest.TestCase):
    def test_returns_error_dict_when_camoufox_unavailable(self):
        with mock.patch.object(osint, "camoufox_available", return_value=False):
            out = osint.osint_search("anything")
        self.assertEqual(out["rows"], [])
        self.assertIn("camoufox not installed", out["error"])

    def test_delegates_to_async_when_available(self):
        async def fake_async(query, max_results=5):
            return {"query": query, "count": 1, "rows": [{"title": "t"}]}

        with mock.patch.object(osint, "camoufox_available", return_value=True), \
                mock.patch.object(osint, "osint_search_async", side_effect=fake_async):
            out = osint.osint_search("q", max_results=3)
        self.assertEqual(out["count"], 1)


class TestCaiToolBuilder(unittest.TestCase):
    def test_returns_none_without_cai(self):
        # CAI is not importable in the offline test env → builder yields None.
        tool = osint.build_osint_search_tool()
        self.assertIsNone(tool)

    def test_effect_is_external(self):
        self.assertEqual(osint.OSINT_SEARCH_EFFECT, "external")


if __name__ == "__main__":
    unittest.main()
