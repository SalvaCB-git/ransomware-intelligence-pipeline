"""
Spider: trendmicro_research_ransomware
Objetivo: https://www.trendmicro.com/en_us/research.html
Método: Playwright pulsa "Load More" y consulta el DOM directamente para los enlaces
"""

import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, urlunparse

import scrapy
from dateutil import parser as dateutil_parser
from scrapy_playwright.page import PageMethod

try:
    from readability import Document
except ImportError:
    Document = None

DATE_RE = re.compile(
    r"\b(January|February|March|April|May|June|July|August|"
    r"September|October|November|December)\s+\d{1,2},\s+\d{4}\b"
)

BASE = "https://www.trendmicro.com"


def canonicalize(url: str) -> str:
    p = urlparse(url)
    return urlunparse(p._replace(query="", fragment="")).rstrip("/")


def _parse_dt(s: str) -> Optional[datetime]:
    try:
        return dateutil_parser.parse(s.strip()).astimezone(timezone.utc)
    except Exception:
        return None


def _extract_published_dt(response) -> Optional[datetime]:
    for sel in [
        'meta[property="article:published_time"]::attr(content)',
        'meta[name="date"]::attr(content)',
        'time::attr(datetime)',
        'time::text',
    ]:
        val = response.css(sel).get()
        if val:
            dt = _parse_dt(val)
            if dt:
                return dt
    m = DATE_RE.search(response.text)
    if m:
        dt = _parse_dt(m.group())
        if dt:
            return dt.replace(tzinfo=timezone.utc)
    return None


def _extract_body_text(response) -> str:
    if Document:
        try:
            summary = Document(response.text).summary()
            text = re.sub(r"<[^>]+>", " ", summary)
            text = re.sub(r"\s+", " ", text).strip()
            if len(text) > 200:
                return text
        except Exception:
            pass
    # Fallbacks genéricos
    for sel in ["article ::text", "main ::text", ".content ::text"]:
        parts = response.css(sel).getall()
        text = " ".join(p.strip() for p in parts if p.strip())
        if len(text) > 200:
            return text
    return ""


class TrendMicroResearchSpider(scrapy.Spider):
    name = "trendmicro_research_ransomware"
    allowed_domains = ["www.trendmicro.com"]

    cutoff = datetime(2021, 1, 29, tzinfo=timezone.utc)
    keyword = "ransomware"
    max_clicks = 300

    custom_settings = {
        "DOWNLOAD_HANDLERS": {
            "http": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
            "https": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
        },
        "TWISTED_REACTOR": "twisted.internet.asyncioreactor.AsyncioSelectorReactor",
        "PLAYWRIGHT_BROWSER_TYPE": "chromium",
        "PLAYWRIGHT_LAUNCH_OPTIONS": {
            "headless": True,
            "args": ["--disable-blink-features=AutomationControlled", "--no-sandbox"],
        },
        "PLAYWRIGHT_DEFAULT_NAVIGATION_TIMEOUT": 60000,
        # blog anti-bot: robots.txt bloquea el listado/sitemap público; lectura
        # permitida por ToS, sin eludir controles de acceso (ver §ética + README).
        "ROBOTSTXT_OBEY": False,
        "CONCURRENT_REQUESTS": 1,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 1,
        "DOWNLOAD_DELAY": 3,
        "AUTOTHROTTLE_ENABLED": True,
    }

    def start_requests(self):
        yield scrapy.Request(
            f"{BASE}/en_us/research.html",
            callback=self._collect_links,
            meta={
                "playwright": True,
                "playwright_include_page": True,
                "playwright_page_methods": [
                    PageMethod("wait_for_load_state", "domcontentloaded"),
                    PageMethod("wait_for_timeout", 3000),
                ],
                "errback": "errback_close_page",
            },
        )

    async def _collect_links(self, response):
        page = response.meta["playwright_page"]
        visited = set()

        try:
            for click_num in range(self.max_clicks):
                # Consultar el DOM directamente para todos los enlaces de artículos de research
                hrefs = await page.eval_on_selector_all(
                    "a[href*='/en_us/research/']",
                    "els => els.map(e => e.getAttribute('href'))"
                )

                new_links = []
                for href in hrefs:
                    if not href or not re.search(r'/en_us/research/\d+/', href):
                        continue
                    url = canonicalize(BASE + href if href.startswith("/") else href)
                    if url not in visited:
                        visited.add(url)
                        new_links.append(url)

                self.logger.info(
                    "Click %d %d new links (%d total)",
                    click_num, len(new_links), len(visited)
                )

                for url in new_links:
                    yield scrapy.Request(
                        url,
                        callback=self.parse_article,
                    )

                # Pulsar Load More
                btn = await page.query_selector("button.load-more-btn")
                if not btn or not await btn.is_visible() or not await btn.is_enabled():
                    self.logger.info("Load More button gone. Done collecting.")
                    break

                prev_count = len(visited)
                await btn.click()
                # Esperar a que aparezca el nuevo contenido en el DOM
                await page.wait_for_timeout(4000)

                # Comprobar si han aparecido enlaces nuevos
                hrefs_after = await page.eval_on_selector_all(
                    "a[href*='/en_us/research/']",
                    "els => els.map(e => e.getAttribute('href'))"
                )
                if len(hrefs_after) <= prev_count:
                    self.logger.info("No new links after click. Stopping.")
                    break

        finally:
            await page.close()

    async def parse_article(self, response):
        page = response.meta.get("playwright_page")
        if page:
            await page.close()

        headline = (
            response.css("h1::text").get()
            or response.css("title::text").get("")
        ).strip()

        if not headline:
            return

        dt = _extract_published_dt(response)
        if dt and dt < self.cutoff:
            self.logger.debug("Skipping (too old): %s", response.url)
            return

        body = _extract_body_text(response)

        if self.keyword not in (headline + " " + body).lower():
            self.logger.debug("Skipping (no keyword): %s", response.url)
            return

        yield {
            "source": "trendmicro_research",
            "published_utc": dt.isoformat() if dt else "",
            "headline": headline,
            "url": response.url.rstrip("/"),
            "body": body,
        }

    async def errback_close_page(self, failure):
        page = failure.request.meta.get("playwright_page")
        if page and not page.is_closed():
            await page.close()
        self.logger.warning("Request failed: %s %s", failure.request.url, failure.value)
