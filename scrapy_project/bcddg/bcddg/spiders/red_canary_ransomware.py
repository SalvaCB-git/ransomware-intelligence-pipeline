import scrapy
import re
from datetime import datetime, timezone
from dateutil import parser
from lxml.html.clean import Cleaner
import lxml.html

def _parse_dt(date_str):
    try:
        return parser.parse(date_str)
    except Exception:
        return None

class RedCanarySpider(scrapy.Spider):
    name = 'red_canary_ransomware'
    allowed_domains = ['redcanary.com']
    
    # URL inicial del RSS
    RSS_URL = 'https://redcanary.com/blog/feed/'
    RSS_BASE = 'https://redcanary.com/blog/feed/'

    # Reusamos la configuración que ya funciona bien en los spiders de Tier 1
    custom_settings = {
        "ROBOTSTXT_OBEY": True,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 1,
        "DOWNLOAD_DELAY": 3,
        "AUTOTHROTTLE_ENABLED": True,
    }

    # Fecha de corte (unos 3 años atrás) y keyword
    cutoff = datetime(2021, 1, 1, tzinfo=timezone.utc)
    keyword = "ransomware"

    def start_requests(self):
        yield scrapy.Request(self.RSS_URL, callback=self.parse_rss, meta={"page": 1})

    def parse_rss(self, response):
        """Parsea el feed RSS XML con pagination."""
        page = response.meta["page"]

        # Quitar namespaces para simplificar las consultas XPath
        # (evita líos con prefijos Atom/DC)
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

            # No filtramos en el RSS (a veces la keyword solo aparece en el cuerpo); lanzamos la request
            yield scrapy.Request(
                url,
                callback=self.parse_article,
                meta={"pub_dt_hint": pub_dt},
            )

        # Pagination al estilo WordPress
        next_page = page + 1
        next_url = f"{self.RSS_BASE}?paged={next_page}"
        yield scrapy.Request(next_url, callback=self.parse_rss, meta={"page": next_page})

    def parse_article(self, response):
        """Parsea una página individual de artículo."""
        pub_dt = response.meta.get("pub_dt_hint")

        # Intentar extraer el título
        title = response.xpath("//h1/text()").get()
        if not title:
            title = response.css("h1::text").get()
        if not title:
            title = response.xpath("//meta[@property='og:title']/@content").get()
        title = title.strip() if title else "No Title"

        # Intentar extraer el cuerpo (Red Canary usa <article> o un div de contenido)
        body_html = response.xpath("//article").get()
        if not body_html:
            # Fallback a divs con clases de post o de contenido
            body_html = response.css("div.post-content, div.entry-content, main, .content").get()

        if not body_html:
            self.logger.warning(f"Could not find article body for {response.url}")
            return

        # Limpiar el HTML y extraer el texto
        try:
            cleaner = Cleaner(scripts=True, style=True, links=False,
                            meta=True, page_structure=False,
                            safe_attrs_only=False, remove_tags=['script', 'style', 'nav', 'header', 'footer', 'aside'])
            cleaned_html = cleaner.clean_html(body_html)
            tree = lxml.html.fromstring(cleaned_html)
            text_content = tree.text_content()
            # Normalizar el texto: colapsar espacios y saltos de línea
            text_content = re.sub(r'\s+', ' ', text_content).strip()
        except Exception as e:
            self.logger.error(f"Error parseando texto en {response.url}: {e}")
            return

        # FILTRO PRINCIPAL: ¿menciona ransomware?
        if self.keyword not in text_content.lower() and self.keyword not in title.lower():
            self.logger.debug(f"Article skipped (no ransomware keyword): {response.url}")
            return

        yield {
            "source": self.name.replace("_ransomware", ""),
            "url": response.url,
            "title": title,
            "date": pub_dt.strftime("%Y-%m-%d") if pub_dt else "1970-01-01",
            "body": text_content,
        }
