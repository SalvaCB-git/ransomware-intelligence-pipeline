"""
Spider del blog de Huntress
===========================

Scrapea artículos de ransomware y threat research del blog de Huntress vía RSS.
HTML estático, no necesita JavaScript.

Fuente: https://www.huntress.com/blog
RSS:    https://www.huntress.com/blog/rss.xml

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


class HuntressSpider(scrapy.Spider):
    """
    Spider para el blog de Huntress (https://www.huntress.com/blog).
    Usa el feed RSS, confirmado activo con entradas hasta 2026.
    Filtra por keyword para quedarse con contenido de ransomware
    (densidad ~45% según el análisis del usuario).
    """

    name = "huntress_ransomware"
    allowed_domains = ["huntress.com", "www.huntress.com"]

    RSS_URL = "https://www.huntress.com/blog/rss.xml"
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
        yield scrapy.Request(self.RSS_URL, callback=self.parse_rss)

    def parse_rss(self, response):
        """Parsea el feed RSS de Huntress (una sola página con todos los artículos)."""
        items = response.xpath("//item")
        self.logger.info(f"Huntress RSS: found {len(items)} items")

        for item in items:
            url = item.xpath("link/text()").get("").strip()
            if not url:
                url = item.xpath("guid/text()").get("").strip()
            if not url:
                continue

            pub_raw = item.xpath("pubDate/text()").get("").strip()
            pub_dt = _parse_dt(pub_raw) if pub_raw else None

            if pub_dt:
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                if pub_dt < self.cutoff:
                    self.logger.info(f"Reached cutoff ({pub_dt.date()}), stopping.")
                    return

            # Pre-filtro usando título y descripción del RSS
            title = item.xpath("title/text()").get("").lower()
            desc = item.xpath("description/text()").get("").lower()
            if self.keyword not in title and self.keyword not in desc:
                self.logger.debug(f"Pre-filter skip: {url}")
                continue

            yield scrapy.Request(
                url,
                callback=self.parse_article,
                meta={"pub_dt_hint": pub_dt},
            )

    def parse_article(self, response):
        """Parsea un post individual del blog de Huntress."""
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
            raw = response.css("time::text").get()
            if raw:
                pub_dt = _parse_dt(raw)
        if not pub_dt:
            # El RSS de Huntress trae pubDate; como fallback miramos el texto de la página
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

        # Verificación final de keyword sobre el artículo completo
        if self.keyword not in (headline + " " + body).lower():
            self.logger.debug(f"No keyword in article: {url}")
            return

        self.logger.info(f"Huntress: {headline[:60]}... ({pub_dt.date()})")

        yield {
            "source": "huntress",
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

        for sel in [".blog-post-body", ".blog-content", "article", ".post-content", ".entry-content", "main"]:
            content = response.css(f"{sel} ::text").getall()
            if content:
                return re.sub(r"\s+", " ", " ".join(content)).strip()
        return ""
