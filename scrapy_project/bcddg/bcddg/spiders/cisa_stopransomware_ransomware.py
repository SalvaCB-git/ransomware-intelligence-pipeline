"""
Spider de CISA #StopRansomware
==============================

Scrapea los advisories de CISA #StopRansomware vía su feed XML.
HTML estático, incluye IDs explícitos de MITRE ATT&CK.

Fuente: https://www.cisa.gov/stopransomware
RSS:    https://www.cisa.gov/cybersecurity-advisories/all.xml

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

class CisaStopRansomwareSpider(scrapy.Spider):
    name = "cisa_stopransomware_ransomware"
    allowed_domains = ["cisa.gov", "www.cisa.gov"]

    # Empezamos por el listado principal de cybersecurity advisories
    start_urls = ["https://www.cisa.gov/news-events/cybersecurity-advisories"]
    cutoff = datetime(2021, 1, 29, tzinfo=timezone.utc)
    keyword = "ransomware"

    custom_settings = {
        "CONCURRENT_REQUESTS": 1,
        "DOWNLOAD_DELAY": 3,
        "ROBOTSTXT_OBEY": True,
        "RETRY_TIMES": 5,
        "RETRY_HTTP_CODES": [500, 502, 503, 504, 408, 429],
    }

    def parse(self, response):
        links = response.css(".c-teaser__content a, .c-teaser__title a")
        self.logger.info(f"Page {response.url} - Found {len(links)} links")
        
        for link in links:
            url = link.css("::attr(href)").get()
            if not url:
                continue
            
            # Construir URL absoluta porque suele venir como ruta relativa
            absolute_url = response.urljoin(url)

            yield scrapy.Request(
                absolute_url,
                callback=self.parse_article
            )

        # Pagination
        next_page = response.css("li.pager__item--next a, a[rel='next']::attr(href)").get()
        if next_page:
            yield response.follow(next_page, callback=self.parse)

    def parse_article(self, response):
        url = canonicalize(response.url)
        if response.status >= 400:
            return

        headline = response.css("h1::text").get()
        if not headline:
            headline = response.css("title::text").get()
        headline = (headline or "").strip()

        pub_dt = response.meta.get("pub_dt_hint")
        if not pub_dt:
            raw = response.css('meta[property="article:published_time"]::attr(content)').get()
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
            return

        body = self._extract_body(response)
        if not body:
            self.logger.warning(f"Empty body: {url}")
            return

        if self.keyword not in (headline + " " + body).lower() and "stopransomware" not in (headline + " " + body).lower():
            self.logger.debug(f"No keyword in article: {url}")
            return

        self.logger.info(f"CISA: {headline[:60]}... ({pub_dt.date()})")

        yield {
            "source": "cisa",
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

        for sel in [".c-field--name-body", "article", ".c-advisory-content", ".content", "main"]:
            content = response.css(f"{sel} ::text").getall()
            if content:
                return re.sub(r"\s+", " ", " ".join(content)).strip()
        return ""
