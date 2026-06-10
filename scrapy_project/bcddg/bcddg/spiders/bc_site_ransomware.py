"""
Spider directo de BleepingComputer
==================================

Extrae artículos sobre ransomware directamente desde BleepingComputer
(https://www.bleepingcomputer.com), sin pasar por un buscador.

Estrategia:
  1. Parsear /sitemap/ para descubrir las raíces de categoría
     (/news/<categoria>/, /tutorials/).
  2. Recorrer la pagination de cada categoría hasta recolectar todas las
     URLs de artículos dentro de la ventana temporal.
  3. Descargar cada artículo y extraer titular, fecha de publicación y cuerpo.
  4. Aplicar el filtro de keyword ("ransomware" por defecto) antes de emitir
     el item.

Campos de salida: published_utc, headline, url, body

Uso:
    cd bcddg
    scrapy crawl bc_site_ransomware -o output.csv
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


# Patrón regex para detectar fechas escritas como "January 15, 2024"
MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
DATE_RE = re.compile(rf"\b({MONTHS})\s+\d{{1,2}},\s+\d{{4}}\b", re.I)


def canonicalize(url: str) -> str:
    """Normaliza una URL quitando query string, fragment y barra final.

    Se usa para deduplicar distintas representaciones de la misma página.
    """
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path.rstrip("/"), "", "", ""))


def is_article_url(url: str) -> bool:
    """Devuelve True si la URL es un artículo de noticias o tutorial de BleepingComputer.

    Comprueba que el host sea www.bleepingcomputer.com y que la ruta empiece
    por /news/ o /tutorials/.
    """
    p = urlparse(url)
    if p.netloc != "www.bleepingcomputer.com":
        return False
    return p.path.startswith("/news/") or p.path.startswith("/tutorials/")


class BcSiteRansomwareSpider(scrapy.Spider):
    """Spider que crawlea BleepingComputer directamente (sin buscador).

    Descubre las raíces de categoría desde /sitemap/, pagina cada una y
    scrapea artículos filtrados por keyword y ventana temporal.
    """

    name = "bc_site_ransomware"
    allowed_domains = ["www.bleepingcomputer.com"]

    # Solo incluir artículos publicados después de esta fecha (ventana de 5 años desde enero 2026)
    keyword = "ransomware"
    cutoff = datetime(2021, 1, 29, tzinfo=timezone.utc)

    # Tope de seguridad: cortar la pagination tras este número de páginas por categoría
    # para evitar bucles infinitos si la categoría no está ordenada por fecha.
    max_pages_per_category = 2000

    def start_requests(self):
        """Arranca el crawl desde el sitemap de BleepingComputer."""
        yield scrapy.Request(
            "https://www.bleepingcomputer.com/sitemap/",
            callback=self.parse_sitemap,
            meta={"download_timeout": 30},
        )

    def parse_sitemap(self, response):
        """Extrae las URLs raíz de categoría desde la página del sitemap.

        Se centra en las secciones /news/ y /tutorials/, ignorando foros y
        páginas de descarga que son demasiado ruidosas para la investigación
        sobre ransomware.
        """
        links = response.css("a::attr(href)").getall()
        roots = set()

        for href in links:
            if not href:
                continue
            if href.startswith("/"):
                href = response.urljoin(href)
            href = canonicalize(href)

            path = urlparse(href).path

            # Quedarnos con páginas de categoría de primer nivel; descartar artículos individuales
            if path.startswith("/news/") and not self._looks_like_article_path(path):
                roots.add(href)
            if path.startswith("/tutorials/") and not self._looks_like_article_path(path):
                roots.add(href)

        # Fallback por si cambia la estructura del sitemap o el parseo no devuelve nada
        if not roots:
            roots = {
                "https://www.bleepingcomputer.com/news/",
                "https://www.bleepingcomputer.com/news/security/",
                "https://www.bleepingcomputer.com/tutorials/",
            }

        for root in sorted(roots):
            yield from self._crawl_category(root, page=1)

    def _crawl_category(self, root: str, page: int):
        """Emite una request para el número de página indicado de la categoría.

        La página 1 es la URL raíz; las siguientes usan el sufijo /page/N/.
        """
        if page == 1:
            url = root
        else:
            url = canonicalize(root) + f"/page/{page}/"

        yield scrapy.Request(
            url,
            callback=self.parse_category,
            cb_kwargs={"root": root, "page": page},
            meta={"download_timeout": 30},
        )

    def parse_category(self, response, root: str, page: int):
        """Extrae URLs de artículos de una página de listado de categoría y lanza una request por cada una.

        También comprueba si la fecha más antigua de la página es anterior al
        cutoff; en ese caso se omiten las páginas siguientes (los artículos
        están ordenados por fecha).
        """
        if response.status >= 400:
            return

        # Recoger todos los enlaces y filtrar para quedarnos con URLs de artículos
        hrefs = response.css("a::attr(href)").getall()
        article_urls = set()
        for href in hrefs:
            if not href:
                continue
            abs_url = response.urljoin(href)
            abs_url = canonicalize(abs_url)
            if is_article_url(abs_url) and self._looks_like_article_path(urlparse(abs_url).path):
                article_urls.add(abs_url)

        for url in sorted(article_urls):
            yield scrapy.Request(
                url,
                callback=self.parse_article,
                meta={"download_timeout": 30},
            )

        # Parar la pagination si esta página ya contiene artículos anteriores al cutoff
        page_dates = self._extract_dates_from_text(response.text)
        if page_dates:
            oldest = min(page_dates)
            if oldest < self.cutoff:
                return

        # Continuar a la siguiente página (acotado por el límite de seguridad)
        if page < self.max_pages_per_category:
            yield from self._crawl_category(root, page=page + 1)

    def parse_article(self, response):
        """Extrae datos de una página individual de artículo.

        Descarta artículos demasiado antiguos o que no contengan la keyword.
        Emite un dict con: published_utc, headline, url, body.
        """
        url = canonicalize(response.url)

        headline = (response.css("h1::text").get() or "").strip()

        published_dt = self._extract_published_dt(response)
        if not published_dt:
            return  # Descartar artículos sin fecha de publicación detectable

        # Asegurar datetime UTC con timezone para que las comparaciones sean consistentes
        if published_dt.tzinfo is None:
            published_dt = published_dt.replace(tzinfo=timezone.utc)
        published_dt = published_dt.astimezone(timezone.utc)

        if published_dt < self.cutoff:
            return  # Artículo anterior a la ventana de investigación

        body = self._extract_body_text(response)

        # Filtro de keyword: se busca tanto en el titular como en el cuerpo
        hay = (headline + " " + body).lower()
        if self.keyword not in hay:
            return

        yield {
            "published_utc": published_dt.isoformat(),
            "headline": headline,
            "url": url,
            "body": body,
        }

    # --- Métodos auxiliares ---
    def _looks_like_article_path(self, path: str) -> bool:
        """Heurística: devuelve True si la ruta parece un artículo y no una categoría.

        Los artículos suelen tener tres o más segmentos, p. ej.:
            /news/security/titulo-del-articulo/
        Las páginas de categoría tienen dos o menos, p. ej.:
            /news/security/
        """
        parts = [p for p in path.split("/") if p]
        if len(parts) < 3:
            return False
        if parts[0] in ("news", "tutorials"):
            return True
        return False

    def _extract_dates_from_text(self, text: str):
        """Busca con regex todas las fechas legibles en el HTML en bruto.

        Devuelve una lista de datetimes UTC con timezone extraídos de patrones
        como "January 15, 2024". Se usa para cortar la pagination antes de tiempo.
        """
        dts = []
        for m in DATE_RE.finditer(text or ""):
            dt = self._parse_dt(m.group(0))
            if dt:
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                dts.append(dt.astimezone(timezone.utc))
        return dts

    def _extract_published_dt(self, response):
        """Prueba varias estrategias para extraer la fecha de publicación del artículo.

        Estrategia A: <meta property="article:published_time"> (la más fiable)
        Estrategia B: regex de "Month DD, YYYY" en el texto de la página
        Estrategia C: <time datetime="..."> o el texto dentro de <time>
        """
        # Estrategia A: meta de fecha de publicación (datos estructurados, preferida)
        meta_time = response.css('meta[property="article:published_time"]::attr(content)').get()
        if meta_time:
            dt = self._parse_dt(meta_time)
            if dt:
                return dt

        # Estrategia B: fecha escrita visible en la página (frecuente en BleepingComputer)
        m = DATE_RE.search(response.text or "")
        if m:
            dt = self._parse_dt(m.group(0))
            if dt:
                return dt

        # Estrategia C: elemento <time> con atributo datetime o texto interno
        t = response.css("time::attr(datetime)").get() or response.css("time::text").get()
        if t:
            dt = self._parse_dt(t)
            if dt:
                return dt

        return None

    def _extract_body_text(self, response) -> str:
        """Extrae el cuerpo principal del artículo como texto plano.

        Prefiere la librería readability-lxml cuando está disponible, porque
        elimina la navegación, las barras laterales y el ruido publicitario.
        Si no, recurre a recoger los párrafos que vienen tras el <h1>.
        """
        if Document is not None:
            try:
                summary_html = Document(response.text).summary(html_partial=True)
                text = " ".join(scrapy.Selector(text=summary_html).css("::text").getall())
                text = re.sub(r"\s+", " ", text).strip()
                if len(text) > 200:
                    return text
            except Exception:
                pass  # Caer al método básico de extracción

        # Fallback básico: recoger todos los párrafos que siguen al titular
        paras = response.xpath("//h1/following::p//text()").getall()
        text = " ".join(p.strip() for p in paras if p.strip())
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def _parse_dt(self, s: str):
        """Parsea una cadena de fecha a un objeto datetime usando dateutil.

        Devuelve None ante cualquier fallo de parseo para permitir degradación elegante.
        """
        try:
            return dateparser.parse(s)
        except Exception:
            return None
