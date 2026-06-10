import subprocess
import re
from datetime import datetime, timezone

import scrapy

CUTOFF = datetime(2021, 1, 29, tzinfo=timezone.utc)
KEYWORD = "ransomware"

SITEMAP_URL = "https://blog.talosintelligence.com/sitemap-posts.xml"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"


def _fetch_sitemap():
    result = subprocess.run(
        ["curl", "-s", "-L", "-A", UA, SITEMAP_URL],
        capture_output=True, text=True, timeout=30
    )
    xml = result.stdout
    entries = re.findall(
        r"<loc>\s*(https://blog\.talosintelligence\.com/[^<\s]+)\s*</loc>\s*<lastmod>\s*([^<\s]+)\s*</lastmod>",
        xml
    )
    return entries


class TalosBlogRansomwareSpider(scrapy.Spider):
    name = "talos_blog_ransomware"
    custom_settings = {
        "CONCURRENT_REQUESTS": 4,
        "DOWNLOAD_DELAY": 2,
        # blog anti-bot: robots.txt bloquea el listado/sitemap público; lectura
        # permitida por ToS, sin eludir controles de acceso (ver §ética + README).
        "ROBOTSTXT_OBEY": False,
        "DEFAULT_REQUEST_HEADERS": {"User-Agent": UA},
    }

    def start_requests(self):
        entries = _fetch_sitemap()
        self.logger.info(f"Sitemap returned {len(entries)} entries")
        filtered = 0
        for url, lastmod in entries:
            try:
                dt = datetime.fromisoformat(lastmod.replace("Z", "+00:00"))
            except ValueError:
                dt = None
            if dt and dt < CUTOFF:
                filtered += 1
                continue
            yield scrapy.Request(url, callback=self.parse_article)
        self.logger.info(f"Filtered {filtered} entries older than cutoff")

    def parse_article(self, response):
        pub = response.css('meta[property="article:published_time"]::attr(content)').get()
        if not pub:
            return
        try:
            dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
            published_utc = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return
        if dt < CUTOFF:
            return

        headline = response.css("h1.text-center::text").get("")
        if not headline:
            headline = response.css("h1::text").get("")
        headline = headline.strip()

        body_parts = response.css("div.post-full-content *::text").getall()
        body = " ".join(p.strip() for p in body_parts if p.strip())

        if KEYWORD.lower() not in (headline + " " + body).lower():
            return

        yield {
            "source": "Cisco Talos Blog",
            "published_utc": published_utc,
            "headline": headline,
            "url": response.url,
            "body": body,
        }
