"""
Spider del Microsoft Security Blog
==================================

Scrapea posts relacionados con ransomware del Microsoft Security Blog vía RSS.
HTML estático, no necesita JavaScript.

Fuente: https://www.microsoft.com/en-us/security/blog
RSS:    https://www.microsoft.com/en-us/security/blog/feed/

Autor: Proyecto Profilling-Ransomware
Propósito: investigación científica sobre amenazas de ransomware
"""

import re
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

import scrapy
from dateutil import parser as dateparser

try:
    from readability import Document
except Exception:
    Document = None

MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
DATE_RE = re.compile(rf"\b({MONTHS})\s+\d{{1,2}},\s+\d{{4}}\b", re.I)


def canonicalize(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path.rstrip("/"), "", "", ""))


def _parse_dt(s: str):
    try:
        return dateparser.parse(s)
    except Exception:
        return None


class MicrosoftSecuritySpider(scrapy.Spider):
    """
    Spider para el Microsoft Security Blog (https://www.microsoft.com/en-us/security/blog).
    Usa el feed RSS con pagination al estilo WordPress (?paged=N).
    Filtra por keyword para quedarse con contenido de ransomware.
    """

    name = "microsoft_security_ransomware"
    allowed_domains = ["microsoft.com", "www.microsoft.com"]

    RSS_BASE = "https://www.microsoft.com/en-us/security/blog/feed/"
    cutoff = datetime(2021, 1, 29, tzinfo=timezone.utc)
    keyword = "ransomware"

    custom_settings = {
        "CONCURRENT_REQUESTS": 1,
        "DOWNLOAD_DELAY": 3,
        "ROBOTSTXT_OBEY": True,
        "RETRY_TIMES": 5,
        "RETRY_HTTP_CODES": [500, 502, 503, 504, 408, 429],
    }

    def start_requests(self):
        yield scrapy.Request(self.RSS_BASE, callback=self.parse_rss, meta={"page": 1})

    def parse_rss(self, response):
        """Parsea el feed RSS XML con pagination."""
        page = response.meta["page"]

        # Quitar namespaces para que las consultas XPath sean más cómodas
        response.selector.remove_namespaces()

        items = response.xpath("//item")

        if not items:
            self.logger.info(f"No items on RSS page {page}, stopping.")
            return

        self.logger.info(f"RSS page {page}: {len(items)} items")

        for item in items:
            url = item.xpath("link/text()").get("").strip()
            if not url:
                continue

            pub_raw = item.xpath("pubDate/text()").get("").strip()
            pub_dt = _parse_dt(pub_raw) if pub_raw else None

            if pub_dt:
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                if pub_dt < self.cutoff:
                    self.logger.info(f"Reached cutoff ({pub_dt.date()}), stopping pagination.")
                    return

            # Quitamos el pre-filtro agresivo del RSS para parsear el artículo entero.
            # Algunos artículos no llevan la keyword en título/descripción pero sí en el cuerpo.

            yield scrapy.Request(
                url,
                callback=self.parse_article,
                meta={"pub_dt_hint": pub_dt},
            )

        # Paginar (pagination del RSS de WordPress)
        next_page = page + 1
        next_url = f"{self.RSS_BASE}?paged={next_page}"
        yield scrapy.Request(next_url, callback=self.parse_rss, meta={"page": next_page})

    def parse_article(self, response):
        """Parsea un post individual del Microsoft Security Blog."""
        url = canonicalize(response.url)

        if response.status >= 400:
            self.logger.warning(f"HTTP {response.status}: {url}")
            return

        # Titular
        headline = response.css("h1::text").get()
        if not headline:
            headline = response.css('meta[property="og:title"]::attr(content)').get()
        if not headline:
            headline = response.css("title::text").get()
        headline = (headline or "").strip()

        # Fecha
        pub_dt = response.meta.get("pub_dt_hint")
        if not pub_dt:
            raw = response.css('meta[property="article:published_time"]::attr(content)').get()
            if raw:
                pub_dt = _parse_dt(raw)
        if not pub_dt:
            raw = response.css("time::attr(datetime)").get()
            if raw:
                pub_dt = _parse_dt(raw)
        if not pub_dt:
            # Microsoft mete la fecha en la URL: /YYYY/MM/DD/
            m = re.search(r"/(\d{4}/\d{2}/\d{2})/", response.url)
            if m:
                pub_dt = _parse_dt(m.group(1))
        if not pub_dt:
            m = DATE_RE.search(response.text or "")
            if m:
                pub_dt = _parse_dt(m.group(0))

        if not pub_dt:
            self.logger.warning(f"No date found: {url}")
            return

        if pub_dt.tzinfo is None:
            pub_dt = pub_dt.replace(tzinfo=timezone.utc)

        if pub_dt < self.cutoff:
            self.logger.debug(f"Too old ({pub_dt.date()}): {url}")
            return

        # Cuerpo
        body = self._extract_body(response)
        if not body:
            self.logger.warning(f"Empty body: {url}")
            return

        # Filtro final por keyword
        if self.keyword not in (headline + " " + body).lower():
            self.logger.debug(f"No keyword in article body: {url}")
            return

        self.logger.info(f"Microsoft Security Blog: {headline[:60]}... ({pub_dt.date()})")

        yield {
            "source": "microsoft_security",
            "published_utc": pub_dt.isoformat(),
            "headline": headline,
            "url": url,
            "body": body,
        }

    def _extract_body(self, response) -> str:
        if Document:
            try:
                summary = Document(response.text).summary(html_partial=True)
                text = " ".join(scrapy.Selector(text=summary).css("::text").getall())
                return re.sub(r"\s+", " ", text).strip()
            except Exception:
                pass

        for sel in [".entry-content.wp-block-post-content", ".entry-content", ".ms-blog-content", "article", ".post-body", "main .content", "main"]:
            content = response.css(f"{sel} ::text").getall()
            if content:
                return re.sub(r"\s+", " ", " ".join(content)).strip()
        return ""
