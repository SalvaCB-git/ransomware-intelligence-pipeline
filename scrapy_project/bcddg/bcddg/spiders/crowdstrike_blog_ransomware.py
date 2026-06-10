import re
import subprocess
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

from scrapy import Spider, Request
from scrapy_playwright.page import PageMethod
from dateutil import parser as dateutil_parser

logger = logging.getLogger(__name__)


def canonicalize(url: str) -> str:
    p = urlparse(url)
    path = p.path.rstrip("/") or "/"
    return urlunparse(p._replace(query="", fragment="", path=path))


DATE_RE = re.compile(
    r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}\b"
)


def _parse_dt(s: str):
    try:
        return dateutil_parser.parse(s)
    except Exception:
        return None


def _fetch_sitemap_urls(sitemap_url: str) -> list:
    """Descarga el sitemap XML con un subprocess de curl y extrae las URLs del blog."""
    try:
        result = subprocess.run(
            ["curl", "-s", "-L", "-A",
             "Mozilla/5.0 Chrome/121.0.0.0",
             sitemap_url],
            capture_output=True, text=True, timeout=30
        )
        urls = re.findall(
            r"<loc>\s*(https://www\.crowdstrike\.com/(?:en-us/)?blog/[^<\s]+)\s*</loc>",
            result.stdout
        )
        return urls
    except Exception as e:
        logger.error(f"Failed to fetch sitemap {sitemap_url}: {e}")
        return []


class CrowdStrikeBlogSpider(Spider):
    name = "crowdstrike_blog_ransomware"
    allowed_domains = ["crowdstrike.com"]

    cutoff = datetime(2021, 1, 29, tzinfo=timezone.utc)
    keyword = "ransomware"

    SITEMAP_URLS = [
        "https://www.crowdstrike.com/post-sitemap.xml",
        "https://www.crowdstrike.com/post-sitemap2.xml",
    ]

    custom_settings = {
        "DOWNLOAD_HANDLERS": {
            "http": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
            "https": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
        },
        "TWISTED_REACTOR": "twisted.internet.asyncioreactor.AsyncioSelectorReactor",
        "PLAYWRIGHT_BROWSER_TYPE": "chromium",
        "PLAYWRIGHT_LAUNCH_OPTIONS": {
            "headless": True,
            "args": ["--disable-blink-features=AutomationControlled"],
        },
        "PLAYWRIGHT_DEFAULT_NAVIGATION_TIMEOUT": 60000,
        "CONCURRENT_REQUESTS": 2,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 1,
        "DOWNLOAD_DELAY": 4,
        # blog anti-bot: robots.txt bloquea el listado/sitemap público; lectura
        # permitida por ToS, sin eludir controles de acceso (ver §ética + README).
        "ROBOTSTXT_OBEY": False,
        "AUTOTHROTTLE_ENABLED": True,
        "AUTOTHROTTLE_START_DELAY": 4,
        "AUTOTHROTTLE_MAX_DELAY": 60,
        "AUTOTHROTTLE_TARGET_CONCURRENCY": 0.5,
        "RETRY_TIMES": 5,
        "RETRY_HTTP_CODES": [500, 502, 503, 504, 408, 429, 403],
        "LOG_LEVEL": "INFO",
    }

    def start_requests(self):
        seen = set()
        for sitemap_url in self.SITEMAP_URLS:
            urls = _fetch_sitemap_urls(sitemap_url)
            logger.info(f"Sitemap {sitemap_url}: found {len(urls)} URLs")
            for url in urls:
                canon = canonicalize(url)
                if canon in seen:
                    continue
                seen.add(canon)
                yield Request(
                    url,
                    callback=self.parse_article,
                    meta={
                        "playwright": True,
                        "playwright_include_page": True,
                        "playwright_page_methods": [
                            PageMethod("wait_for_load_state", "networkidle"),
                        ],
                        "errback": self.errback,
                    },
                )

    async def parse_article(self, response):
        page = response.meta.get("playwright_page")
        try:
            url = canonicalize(response.url)

            # --- Titular ---
            headline = ""
            try:
                el = await page.query_selector("h1")
                if el:
                    headline = (await el.inner_text()).strip()
            except Exception:
                pass
            if not headline:
                headline = response.css("title::text").get("").strip()

            # --- Fecha ---
            pub_dt = None
            try:
                el = await page.query_selector(".date")
                if el:
                    raw = (await el.inner_text()).strip()
                    pub_dt = _parse_dt(raw)
            except Exception:
                pass

            if not pub_dt:
                try:
                    el = await page.query_selector('meta[property="article:published_time"]')
                    if el:
                        raw = await el.get_attribute("content")
                        pub_dt = _parse_dt(raw)
                except Exception:
                    pass

            if not pub_dt:
                try:
                    text = await page.inner_text("body")
                    m = DATE_RE.search(text)
                    if m:
                        pub_dt = _parse_dt(m.group(0))
                except Exception:
                    pass

            if not pub_dt:
                logger.warning(f"No date found: {url}")
                return

            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=timezone.utc)
            else:
                pub_dt = pub_dt.astimezone(timezone.utc)

            if pub_dt < self.cutoff:
                logger.debug(f"Skipping (too old): {url}")
                return

            # --- Cuerpo ---
            body = ""
            for sel in [".container-wp--main-content-blog", "article", "main", ".post-content", ".entry-content"]:
                try:
                    el = await page.query_selector(sel)
                    if el:
                        body = (await el.inner_text()).strip()
                        if len(body) > 200:
                            break
                except Exception:
                    pass

            if not body:
                logger.warning(f"Empty body: {url}")
                return

            # --- Filtro de keyword ---
            if self.keyword not in (headline + " " + body).lower():
                logger.debug(f"Skipping (no keyword): {url}")
                return

            yield {
                "source": "crowdstrike",
                "published_utc": pub_dt.isoformat(),
                "headline": headline,
                "url": url,
                "body": body,
            }

        finally:
            await page.close()

    async def errback(self, failure):
        page = failure.request.meta.get("playwright_page")
        if page:
            await page.close()
        logger.error(f"Request failed: {failure.request.url} {failure.value}")
