"""
Spider: cisco_talos_ransomware
Objetivo: https://blog.talosintelligence.com/
Método: pagination mediante /page/N/
"""
import re
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional
import scrapy
from dateutil import parser as dateutil_parser
try:
    from readability import Document
except ImportError:
    Document = None

class CiscoTalosSpider(scrapy.Spider):
    name = "cisco_talos_ransomware"
    allowed_domains = ["blog.talosintelligence.com"]
    start_urls = ["https://blog.talosintelligence.com/"]
    cutoff = datetime(2021, 1, 29, tzinfo=timezone.utc)
    keyword = "ransomware"
    max_pages = 500
    _current_page = 1
    custom_settings = {"CONCURRENT_REQUESTS": 1, "CONCURRENT_REQUESTS_PER_DOMAIN": 1, "DOWNLOAD_DELAY": 4}

    def parse(self, response):
        yield from self._parse_listing(response)

    def _parse_listing(self, response):
        seen = set()
        for href in response.css("article a::attr(href), h2 a::attr(href), h3 a::attr(href)").getall():
            url = response.urljoin(href)
            path = urlparse(url).path
            if any(skip in path for skip in ("/page/", "/category/", "/author/", "/tag/")):
                continue
            if url not in seen and path.count("-") >= 1:
                seen.add(url)
                yield scrapy.Request(url, callback=self.parse_article)
        if self._current_page < self.max_pages:
            dates = response.css('time::attr(datetime)').getall()
            stop = any(True for d in dates if self._parse_dt(d) and self._parse_dt(d) < self.cutoff)
            if not stop:
                self._current_page += 1
                yield scrapy.Request(f"https://blog.talosintelligence.com/page/{self._current_page}/", callback=self._parse_listing)

    def _parse_dt(self, s) -> Optional[datetime]:
        try:
            return dateutil_parser.parse(s).astimezone(timezone.utc)
        except Exception:
            return None

    def parse_article(self, response):
        headline = (response.css("h1::text").get() or response.css("title::text").get("")).strip()
        if not headline:
            return
        dt = self._extract_date(response)
        if dt and dt < self.cutoff:
            return
        body = self._extract_body(response)
        if self.keyword not in (headline + " " + body).lower():
            return
        yield {"source": "cisco_talos", "published_utc": dt.isoformat() if dt else "", "headline": headline, "url": response.url.rstrip("/"), "body": body}

    def _extract_date(self, response) -> Optional[datetime]:
        for sel in ['meta[property="article:published_time"]::attr(content)', 'time::attr(datetime)', 'time::text']:
            val = response.css(sel).get()
            if val:
                try:
                    return dateutil_parser.parse(val).astimezone(timezone.utc)
                except Exception:
                    pass
        m = re.search(r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}\b', response.text)
        if m:
            try:
                return dateutil_parser.parse(m.group()).replace(tzinfo=timezone.utc)
            except Exception:
                pass
        return None

    def _extract_body(self, response) -> str:
        if Document:
            try:
                text = re.sub(r'<[^>]+>', ' ', Document(response.text).summary())
                text = re.sub(r'\s+', ' ', text).strip()
                if len(text) > 200:
                    return text
            except Exception:
                pass
        parts = response.css(".entry-content ::text, article ::text, main ::text").getall()
        return " ".join(p.strip() for p in parts if p.strip())
