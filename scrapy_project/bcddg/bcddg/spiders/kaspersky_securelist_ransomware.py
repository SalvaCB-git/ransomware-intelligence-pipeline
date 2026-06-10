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

class SecurelistSpider(scrapy.Spider):
    name = 'kaspersky_securelist_ransomware'
    allowed_domains = ['securelist.com']
    
    # URL inicial del RSS
    RSS_URL = 'https://securelist.com/feed/'
    RSS_BASE = 'https://securelist.com/feed/'

    custom_settings = {
        # blog anti-bot: robots.txt bloquea el listado/sitemap público; lectura
        # permitida por ToS, sin eludir controles de acceso (ver §ética + README).
        "ROBOTSTXT_OBEY": False,
        "CONCURRENT_REQUESTS_PER_DOMAIN": 1,
        "DOWNLOAD_DELAY": 3,
        "AUTOTHROTTLE_ENABLED": True,
    }

    cutoff = datetime(2021, 1, 1, tzinfo=timezone.utc)
    keyword = "ransomware"

    def start_requests(self):
        yield scrapy.Request(self.RSS_URL, callback=self.parse_rss, meta={"page": 1})

    def parse_rss(self, response):
        page = response.meta["page"]
        
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

            yield scrapy.Request(
                url,
                callback=self.parse_article,
                meta={"pub_dt_hint": pub_dt},
            )

        next_page = page + 1
        next_url = f"{self.RSS_BASE}?paged={next_page}"
        yield scrapy.Request(next_url, callback=self.parse_rss, meta={"page": next_page})

    def parse_article(self, response):
        pub_dt = response.meta.get("pub_dt_hint")

        title = response.xpath("//h1/text()").get()
        if not title:
            title = response.xpath("//meta[@property='og:title']/@content").get()
        title = title.strip() if title else "No Title"

        # Cuerpo en Securelist
        body_html = response.xpath("//article").get()
        if not body_html:
            body_html = response.css("div.post-content, div.entry-content, main, .content").get()

        if not body_html:
            self.logger.warning(f"Could not find article body for {response.url}")
            return

        try:
            cleaner = Cleaner(scripts=True, style=True, links=False,
                            meta=True, page_structure=False,
                            safe_attrs_only=False, remove_tags=['script', 'style', 'nav', 'header', 'footer', 'aside'])
            cleaned_html = cleaner.clean_html(body_html)
            tree = lxml.html.fromstring(cleaned_html)
            text_content = tree.text_content()
            text_content = re.sub(r'\s+', ' ', text_content).strip()
        except Exception as e:
            self.logger.error(f"Error parseando texto en {response.url}: {e}")
            return

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
