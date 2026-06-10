"""
Spider de Elastic Security Labs
===============================

Scrapea artículos de threat research de Elastic Security Labs vía su sitemap.
El sitemap expone TODOS los artículos históricos con fechas (el RSS solo
expone uno).

Fuente: https://www.elastic.co/security-labs
Sitemap: https://www.elastic.co/security-labs/sitemap.xml

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


class ElasticSecuritySpider(scrapy.Spider):
    """
    Spider para Elastic Security Labs (https://www.elastic.co/security-labs).
    Usa el sitemap completo para descubrir TODOS los artículos históricos con
    sus fechas. El feed RSS solo expone 1 item; el sitemap es el índice completo.
    Filtra por keyword para quedarse únicamente con contenido de ransomware.
    """

    name = "elastic_security_ransomware"
    allowed_domains = ["elastic.co", "www.elastic.co"]

    SITEMAP_URL = "https://www.elastic.co/security-labs/sitemap.xml"
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
        yield scrapy.Request(self.SITEMAP_URL, callback=self.parse_sitemap)

    def parse_sitemap(self, response):
        """Parsea el sitemap XML para extraer todas las URLs de artículos con su lastmod."""
        response.selector.remove_namespaces()
        urls = response.xpath("//url")
        self.logger.info(f"Sitemap: found {len(urls)} URLs")

        for url_node in urls:
            loc = url_node.xpath("loc/text()").get("").strip()
            lastmod = url_node.xpath("lastmod/text()").get("").strip()

            # Saltarse la propia página índice
            if not loc or loc == "https://www.elastic.co/security-labs":
                continue

            pub_dt = _parse_dt(lastmod) if lastmod else None
            if pub_dt:
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                if pub_dt < self.cutoff:
                    # El sitemap viene ordenado de más nuevo a más viejo: si pasamos el cutoff, paramos
                    self.logger.info(f"Reached cutoff ({pub_dt.date()}), stopping.")
                    return

            yield scrapy.Request(
                loc,
                callback=self.parse_article,
                meta={"pub_dt_hint": pub_dt},
            )

    def parse_article(self, response):
        """Parsea un artículo individual de Elastic Security Labs."""
        url = canonicalize(response.url)

        if response.status >= 400:
            self.logger.warning(f"HTTP {response.status}: {url}")
            return

        # Titular
        headline = response.css("h1::text").get()
        if not headline:
            headline = response.css('meta[property="og:title"]::attr(content)').get()
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

        # Filtro de keyword (confirmado a nivel de artículo)
        if self.keyword not in (headline + " " + body).lower():
            self.logger.debug(f"No keyword in article: {url}")
            return

        self.logger.info(f"Elastic Security Labs: {headline[:60]}... ({pub_dt.date()})")

        yield {
            "source": "elastic_security_labs",
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

        for sel in ["article", ".security-labs-post", ".post-content", ".entry-content", "main"]:
            content = response.css(f"{sel} ::text").getall()
            if content:
                return re.sub(r"\s+", " ", " ".join(content)).strip()
        return ""
