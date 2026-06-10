"""
Spider del blog de SentinelOne
==============================

Spider para scrapear artículos de ciberseguridad del blog de SentinelOne.
Usa requests HTTP estándar con middlewares anti-scraping.

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
    """Normaliza una URL."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path.rstrip("/"), "", "", ""))

class SentinelOneBlogSpider(scrapy.Spider):
    """
    Spider para el blog de SentinelOne (https://www.sentinelone.com/blog/).
    Usa requests HTTP estándar con cabeceras reforzadas contra anti-scraping.
    """

    name = "sentinelone_blog_ransomware"
    allowed_domains = ["sentinelone.com", "www.sentinelone.com"]
    start_urls = ["https://www.sentinelone.com/blog/"]

    keyword = "ransomware"
    cutoff = datetime(2021, 1, 29, tzinfo=timezone.utc)
    max_pages = None  # Sin límite: scrapear todas las páginas

    # Configuración conservadora
    custom_settings = {
        'CONCURRENT_REQUESTS': 2,
        'DOWNLOAD_DELAY': 5,
        'ROBOTSTXT_OBEY': True,
    }

    def parse(self, response):
        """Parsea los listados de artículos de la página del blog."""
        if "text" not in response.headers.get("Content-Type", b"").decode("utf-8", errors="ignore"):
            self.logger.warning("Skipping non-text: %s", response.url)
            return
        if response.status >= 400:
            self.logger.error(f"Error {response.status}: {response.url}")
            return

        # Extraer enlaces a artículos: patrones habituales de blog.
        # Probamos varios selectores hasta encontrar artículos.
        try:
            article_links = response.css('article a::attr(href)').getall()
        except Exception:
            self.logger.warning("Non-text response, skipping: %s", response.url)
            return
        if not article_links:
            article_links = response.css('h2 a::attr(href)').getall()
        if not article_links:
            article_links = response.css('h3 a::attr(href)').getall()
        if not article_links:
            # Probar selectores por atributo de datos o por clase
            article_links = response.css('.post-title a::attr(href)').getall()
        if not article_links:
            article_links = response.css('.blog-post a::attr(href)').getall()

        # Filtrar a URLs únicas de posts del blog
        seen = set()
        unique_links = []
        for href in article_links:
            url = response.urljoin(href)
            if self._is_valid_article(url) and url not in seen:
                seen.add(url)
                unique_links.append(url)

        self.logger.info(f"Found {len(unique_links)} unique articles on {response.url}")

        for url in unique_links:
            yield scrapy.Request(url, callback=self.parse_article)

        # Pagination: patrones habituales
        next_page = response.css('a.next::attr(href)').get()
        if not next_page:
            next_page = response.css('a[rel="next"]::attr(href)').get()
        if not next_page:
            next_page = response.css('.pagination a:contains("Next")::attr(href)').get()
        if not next_page:
            next_page = response.css('.pagination a:contains("")::attr(href)').get()

        if next_page:
            next_page = response.urljoin(next_page)
            # Detectar bucle autorreferente (la última página apunta a sí misma)
            current_url = canonicalize(response.url)
            next_url = canonicalize(next_page)
            if next_url == current_url:
                self.logger.info(f"Reached last page: {response.url}")
                return
            self.logger.info(f"Following pagination: {next_page}")
            yield scrapy.Request(next_page, callback=self.parse)

    def parse_article(self, response):
        """Parsea cada artículo individual del blog."""
        url = canonicalize(response.url)

        # Título: varios fallbacks
        headline = response.css("h1::text").get()
        if not headline:
            headline = response.css("title::text").get()
        if not headline:
            headline = response.css('meta[property="og:title"]::attr(content)').get()
        headline = (headline or "").strip()

        # Extracción de la fecha
        published_dt = self._extract_published_dt(response)
        if not published_dt:
            self.logger.debug(f"No date found for {url}")
            return

        if published_dt.tzinfo is None:
            published_dt = published_dt.replace(tzinfo=timezone.utc)

        if published_dt < self.cutoff:
            self.logger.debug(f"Article too old ({published_dt}): {url}")
            return

        # Extracción del cuerpo
        body = self._extract_body_text(response)

        # Filtro de keyword
        hay = (headline + " " + body).lower()
        if self.keyword not in hay:
            self.logger.debug(f"Keyword '{self.keyword}' not found in: {url}")
            return

        self.logger.info(f"Scraped SentinelOne: {headline[:50]}... ({published_dt.date()})")
        
        yield {
            "source": "sentinelone",
            "published_utc": published_dt.isoformat(),
            "headline": headline,
            "url": url,
            "body": body,
        }

    def _is_valid_article(self, url: str) -> bool:
        """Descarta URLs que no sean de artículos."""
        # Evitar páginas de category/tag/author
        if any(x in url for x in ["/category/", "/tag/", "/author/", "/page/"]):
            return False
        # Solo aceptar URLs de posts del blog
        if "/blog/" in url and url != "https://www.sentinelone.com/blog/":
            return True
        return False

    def _extract_published_dt(self, response):
        """Extrae la fecha de publicación del artículo."""
        # Etiquetas meta
        meta_dt = response.css('meta[property="article:published_time"]::attr(content)').get()
        if meta_dt:
            return self._parse_dt(meta_dt)

        meta_dt = response.css('meta[name="publish-date"]::attr(content)').get()
        if meta_dt:
            return self._parse_dt(meta_dt)

        # Etiquetas <time>
        time_tag = response.css('time::attr(datetime)').get()
        if time_tag:
            return self._parse_dt(time_tag)

        time_text = response.css('time::text').get()
        if time_text:
            return self._parse_dt(time_text)

        # Búsqueda con regex en el texto de la página
        m = DATE_RE.search(response.text or "")
        if m:
            return self._parse_dt(m.group(0))

        return None

    def _parse_dt(self, s: str):
        """Parsea una cadena de fecha."""
        try:
            return dateparser.parse(s)
        except Exception:
            return None

    def _extract_body_text(self, response) -> str:
        """Extrae el texto del cuerpo principal del artículo."""
        if Document:
            try:
                summary = Document(response.text).summary(html_partial=True)
                text = " ".join(scrapy.Selector(text=summary).css("::text").getall())
                return re.sub(r"\s+", " ", text).strip()
            except Exception:
                pass

        # Fallback: selectores de contenido habituales
        content = response.css('article ::text').getall()
        if not content:
            content = response.css('.post-content ::text').getall()
        if not content:
            content = response.css('.entry-content ::text').getall()
        if not content:
            content = response.css('main ::text').getall()
            
        text = " ".join(content)
        return re.sub(r"\s+", " ", text).strip()
