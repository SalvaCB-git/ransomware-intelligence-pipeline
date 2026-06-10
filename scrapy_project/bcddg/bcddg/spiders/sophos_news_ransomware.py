"""
Spider de Sophos News con Playwright
====================================

Spider para scrapear artículos de ciberseguridad de Sophos News.
Usa Playwright para manejar JavaScript y las protecciones anti-bot.

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

class SophosNewsRansomwareSpider(scrapy.Spider):
    """
    Spider para Sophos News (https://news.sophos.com/en-us/).
    Usa Playwright para renderizar las páginas y saltarse las protecciones.
    """

    name = "sophos_news_ransomware"
    allowed_domains = ["www.sophos.com"]
    start_urls = ["https://www.sophos.com/en-us/blog/"]

    keyword = "ransomware"
    cutoff = datetime(2021, 1, 29, tzinfo=timezone.utc)
    max_pages = 50  # Límite de seguridad

    # Configuración de Playwright
    custom_settings = {
        'DOWNLOAD_HANDLERS': {
            "http": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
            "https": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
        },
        'TWISTED_REACTOR': "twisted.internet.asyncioreactor.AsyncioSelectorReactor",
        # blog anti-bot: robots.txt bloquea el listado/sitemap público; lectura
        # permitida por ToS, sin eludir controles de acceso (ver §ética + README).
        'ROBOTSTXT_OBEY': False,
        'PLAYWRIGHT_BROWSER_TYPE': 'chromium',
        'PLAYWRIGHT_LAUNCH_OPTIONS': {
            'headless': True,
            'args': [
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-http2',  # Desactivar HTTP/2 para evitar errores de protocolo
                '--ignore-certificate-errors',
            ],
        },
        'CONCURRENT_REQUESTS': 1,
        'DOWNLOAD_DELAY': 5,
        'PLAYWRIGHT_CONTEXT_ARGS': {
            'ignore_https_errors': True,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        },
        'PLAYWRIGHT_DEFAULT_NAVIGATION_TIMEOUT': 120000,  # 60 segundos
    }

    def start_requests(self):
        """Arranca el scraping desde la página principal."""
        for url in self.start_urls:
            yield scrapy.Request(
                url,
                callback=self.parse,
                meta={
                    "playwright": True,
                    "playwright_include_page": True,
                    "playwright_page_goto_kwargs": {
                        "wait_until": "domcontentloaded",
                    },
                    "playwright_page_methods": [
                        # Esperar por posible contenido dinámico tras cargar el DOM
                        ("wait_for_timeout", 5000),
                    ],
                },
            )

    def parse(self, response):
        """Parsea los listados de artículos y la pagination."""
        if response.status >= 400:
            self.logger.error(f"Error accessing {response.url}: {response.status}")
            return

        # 1. Extraer artículos.
        # Estructura habitual de Sophos: <h2 class="entry-title"><a href="...">
        article_links = response.css('h2.entry-title a::attr(href)').getall()
        # Selectores de fallback
        if not article_links:
            article_links = response.css('article a.more-link::attr(href)').getall()
        if not article_links:
             article_links = response.css('h3 a::attr(href)').getall()

        current_page_articles = 0
        for href in article_links:
            url = response.urljoin(href)
            if self._is_valid_article(url):
                current_page_articles += 1
                yield scrapy.Request(
                    url,
                    callback=self.parse_article,
                    meta={
                        "playwright": True,
                        "playwright_include_page": True,
                        "playwright_page_goto_kwargs": {
                            "wait_until": "domcontentloaded",
                        },
                        "playwright_page_methods": [
                            ("wait_for_timeout", 1000),
                        ],
                    }
                )
        
        self.logger.info(f"Found {current_page_articles} articles on {response.url}")

        # 2. Pagination
        # Buscar "Older Posts", "Next" o números de página
        next_page = response.css('a.next.page-numbers::attr(href)').get()
        if not next_page:
            next_page = response.css('a.next-posts-link::attr(href)').get() # ¿Estándar de WordPress?
        if not next_page:
            # Probar a buscar un enlace genérico con texto "next" u "older"
            next_page = response.xpath('//a[contains(text(), "Next") or contains(text(), "Older")]/@href').get()

        if next_page:
            next_page = response.urljoin(next_page)
            # Comprobar el límite de páginas (heurística sobre la URL /page/X/)
            match = re.search(r'/page/(\d+)/', next_page)
            if match:
                page_num = int(match.group(1))
                if page_num > self.max_pages:
                    self.logger.info(f"Reached max pages limit ({self.max_pages})")
                    return
            
            self.logger.info(f"Following pagination: {next_page}")
            yield scrapy.Request(
                next_page,
                callback=self.parse,
                meta={
                    "playwright": True,
                    "playwright_include_page": True,
                    "playwright_page_goto_kwargs": {
                        "wait_until": "domcontentloaded",
                    },
                }
            )

    def parse_article(self, response):
        """Parsea el contenido de un artículo individual."""
        url = canonicalize(response.url)

        # Título
        headline = response.css("h1.entry-title::text").get()
        if not headline:
             headline = response.css("h1::text").get()
        headline = (headline or "").strip()

        # Fecha
        published_dt = self._extract_published_dt(response)
        if not published_dt:
            self.logger.debug(f"No date found for {url}")
            return

        # Normalizar la fecha
        if published_dt.tzinfo is None:
            published_dt = published_dt.replace(tzinfo=timezone.utc)

        if published_dt < self.cutoff:
            self.logger.debug(f"Article too old ({published_dt}): {url}")
            # Opcional: avisar para parar si fuera cronológico, pero los blogs pueden mezclar fechas
            return

        # Cuerpo
        body = self._extract_body_text(response)

        # Filtro de keyword
        hay = (headline + " " + body).lower()
        if self.keyword not in hay:
            self.logger.debug(f"Keyword '{self.keyword}' not found in: {url}")
            return

        self.logger.info(f"Scraped Sophos: {headline[:50]}... ({published_dt.date()})")
        
        yield {
            "source": "sophos",
            "published_utc": published_dt.isoformat(),
            "headline": headline,
            "url": url,
            "body": body,
        }

    # ================ Auxiliares ================

    def _is_valid_article(self, url: str) -> bool:
        # Evitar páginas de category/tag/author que asomen en los listados
        if "/tag/" in url or "/category/" in url or "/author/" in url:
            return False
        return True

    def _extract_published_dt(self, response):
        # 1. Etiqueta meta
        meta_dt = response.css('meta[property="article:published_time"]::attr(content)').get()
        if meta_dt: return self._parse_dt(meta_dt)

        # 2. Etiqueta <time>
        time_tag = response.css('time.entry-date::attr(datetime)').get()
        if time_tag: return self._parse_dt(time_tag)

        # 3. Regex sobre el texto
        m = DATE_RE.search(response.text or "")
        if m: return self._parse_dt(m.group(0))

        return None

    def _parse_dt(self, s: str):
        try:
            return dateparser.parse(s)
        except Exception:
            return None

    def _extract_body_text(self, response) -> str:
        if Document:
            try:
                summary = Document(response.text).summary(html_partial=True)
                text = " ".join(scrapy.Selector(text=summary).css("::text").getall())
                return re.sub(r"\s+", " ", text).strip()
            except Exception:
                pass
        
        # Fallback: div de contenido específico de Sophos
        content = response.css('div.entry-content ::text').getall()
        if not content:
            content = response.css('article ::text').getall()
            
        text = " ".join(content)
        return re.sub(r"\s+", " ", text).strip()
