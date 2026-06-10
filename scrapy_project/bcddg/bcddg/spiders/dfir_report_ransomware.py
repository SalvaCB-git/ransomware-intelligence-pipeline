"""
Spider de The DFIR Report
=========================

Scrapea informes de incidentes de ransomware en thedfirreport.com vía
su feed RSS. Sitio basado en WordPress, no necesita JavaScript.

Fuente: https://thedfirreport.com
RSS:    https://thedfirreport.com/feed/

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


class DFIRReportSpider(scrapy.Spider):
    """
    Spider para The DFIR Report (https://thedfirreport.com).
    Usa la pagination del feed RSS para descubrir artículos y luego descarga
    cada página individual. Por la naturaleza de la fuente, todo el contenido
    está relacionado con ransomware o intrusiones.
    """

    name = "dfir_report_ransomware"
    allowed_domains = ["thedfirreport.com"]

    RSS_BASE = "https://thedfirreport.com/feed/"
    cutoff = datetime(2021, 1, 29, tzinfo=timezone.utc)
    keyword = "ransomware"

    custom_settings = {
        "CONCURRENT_REQUESTS": 1,
        "DOWNLOAD_DELAY": 4,
        "ROBOTSTXT_OBEY": True,
        "RETRY_TIMES": 5,
        "RETRY_HTTP_CODES": [500, 502, 503, 504, 408, 429],
    }

    def start_requests(self):
        yield scrapy.Request(self.RSS_BASE, callback=self.parse_rss, meta={"page": 1})

    def parse_rss(self, response):
        """Parsea una página del feed RSS XML y sigue la pagination."""
        page = response.meta["page"]

        # Extraer URLs de artículos desde las etiquetas <link> de cada item RSS.
        # En el RSS de WordPress cada <item> tiene un <link> (no atributo href,
        # sino texto del nodo). Usamos XPath porque es XML.
        items = response.xpath("//item")
        if not items:
            self.logger.info(f"No items on RSS page {page}, stopping pagination.")
            return

        self.logger.info(f"RSS page {page}: found {len(items)} items")

        for item in items:
            url = item.xpath("link/text()").get("").strip()
            pub_raw = item.xpath("pubDate/text()").get("").strip()

            if not url:
                continue

            pub_dt = _parse_dt(pub_raw) if pub_raw else None
            if pub_dt:
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                if pub_dt < self.cutoff:
                    self.logger.info(f"Reached cutoff date ({pub_dt.date()}), stopping pagination.")
                    return

            yield scrapy.Request(
                url,
                callback=self.parse_article,
                meta={"pub_dt_hint": pub_dt},
            )

        # Paginar: el RSS de WordPress acepta ?paged=N
        next_page = page + 1
        next_url = f"{self.RSS_BASE}?paged={next_page}"
        yield scrapy.Request(next_url, callback=self.parse_rss, meta={"page": next_page})

    def parse_article(self, response):
        """Descarga el cuerpo completo del artículo desde la página del post."""
        url = canonicalize(response.url)

        if response.status >= 400:
            self.logger.warning(f"HTTP {response.status}: {url}")
            return

        # Titular
        headline = response.css("h1.entry-title::text").get()
        if not headline:
            headline = response.css("h1::text").get()
        if not headline:
            headline = response.css('meta[property="og:title"]::attr(content)').get()
        headline = (headline or "").strip()

        # Fecha: probar varias fuentes
        pub_dt = response.meta.get("pub_dt_hint")
        if not pub_dt:
            # Etiquetas meta
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

        # DFIR Report ya trata casi siempre de ransomware/intrusiones, así que el filtro es generoso
        combined = (headline + " " + body).lower()
        if self.keyword not in combined and "intrusion" not in combined and "threat" not in combined:
            self.logger.debug(f"No keyword match: {url}")
            return

        self.logger.info(f"DFIR Report: {headline[:60]}... ({pub_dt.date()})")

        yield {
            "source": "dfir_report",
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

        for sel in [".entry-content", "article .post-content", "article", ".post-body", "main"]:
            content = response.css(f"{sel} ::text").getall()
            if content:
                return re.sub(r"\s+", " ", " ".join(content)).strip()
        return ""
