"""
Middlewares avanzados anti-scraping
====================================

Este módulo contiene middlewares pensados para evitar que detecten al
crawler o lo bloqueen mientras navega. Está diseñado para una investigación
académica sobre ciberseguridad.

Autor: Proyecto Profilling-Ransomware
Propósito: investigación científica sobre amenazas ransomware
"""

import random
import time
from urllib.parse import urlparse
from scrapy import signals


class RotateUserAgentMiddleware:
    """
    Va rotando el User-Agent para que cada petición parezca venir de un
    navegador distinto.

    Así se evita que el sitio detecte un patrón de bot mirando el User-Agent.
    Usa cadenas de navegadores populares actualizadas a 2026.
    """

    # Lista de User-Agents reales y recientes (2025-2026).
    user_agents = [
        # Chrome en Windows 11
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',

        # Chrome en macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',

        # Firefox en Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',

        # Firefox en macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0',

        # Safari en macOS
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',

        # Edge en Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
    ]

    def process_request(self, request, spider):
        """Pone un User-Agent al azar en cada petición."""
        ua = random.choice(self.user_agents)
        request.headers['User-Agent'] = ua

        # Cabeceras extra para que la petición parezca más realista.
        request.headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        request.headers['Accept-Language'] = 'en-US,en;q=0.9,es;q=0.8'
        request.headers['Accept-Encoding'] = 'gzip, deflate, br'
        request.headers['DNT'] = '1'  # Do Not Track
        request.headers['Connection'] = 'keep-alive'
        request.headers['Upgrade-Insecure-Requests'] = '1'
        request.headers['Sec-Fetch-Dest'] = 'document'
        request.headers['Sec-Fetch-Mode'] = 'navigate'
        request.headers['Sec-Fetch-Site'] = 'none'
        request.headers['Sec-Fetch-User'] = '?1'
        request.headers['Cache-Control'] = 'max-age=0'


class HumanLikeDelayMiddleware:
    """
    Imita el comportamiento humano con pausas variables entre peticiones.

    Usar retardos fijos delata al bot; aquí se sortean tiempos aleatorios
    con una distribución más parecida a la de una persona navegando.
    """

    def __init__(self):
        self.last_request_time = {}

    def process_request(self, request, spider):
        """Espera un tiempo aleatorio antes de cada petición."""
        domain = urlparse(request.url).netloc

        # Mira cuánto ha pasado desde la última petición a este dominio.
        if domain in self.last_request_time:
            elapsed = time.time() - self.last_request_time[domain]

            # Espera mínima aleatoria de 2 a 5 segundos.
            # De vez en cuando hace una "pausa" más larga, como si alguien se parara a leer.
            if random.random() < 0.1:  # 10% de probabilidad
                delay = random.uniform(10, 30)  # "Pausa para leer el artículo"
                spider.logger.debug(f"Long pause: {delay:.1f}s (simulating reading)")
            else:
                delay = random.uniform(2, 5)  # Navegación normal

            remaining_delay = max(0, delay - elapsed)
            if remaining_delay > 0:
                spider.logger.debug(f"Delay: {remaining_delay:.1f}s to {domain}")
                time.sleep(remaining_delay)

        self.last_request_time[domain] = time.time()


class RefererMiddleware:
    """
    Añade un Referer creíble a cada petición para que parezca navegación natural.

    Las peticiones sin Referer o con uno incoherente levantan sospechas.
    Este middleware construye una cadena de Referers que tenga sentido.
    """

    def __init__(self):
        self.last_url = {}

    def process_request(self, request, spider):
        """Pone el Referer adecuado según el contexto."""
        domain = urlparse(request.url).netloc

        # Para la primera página simulamos que venimos de Google.
        if not hasattr(request, 'meta') or not request.meta.get('referer_set'):
            if hasattr(spider, 'start_urls') and request.url in spider.start_urls:
                # Hacemos como si veníamos de una búsqueda en Google.
                request.headers['Referer'] = 'https://www.google.com/'
            else:
                # Usa como Referer la URL anterior del mismo dominio.
                if domain in self.last_url:
                    request.headers['Referer'] = self.last_url[domain]
                else:
                    # Si no hay URL previa, también fingimos venir de Google.
                    request.headers['Referer'] = 'https://www.google.com/'

        # Guarda esta URL como la última visitada del dominio.
        self.last_url[domain] = request.url

        # Marca la petición para no volver a tocarle el Referer.
        if not hasattr(request, 'meta'):
            request.meta = {}
        request.meta['referer_set'] = True


class SessionManagementMiddleware:
    """
    Gestiona cookies y sesiones de forma persistente.

    Algunas páginas necesitan cookies de sesión válidas. Este middleware
    guarda las cookies y las reutiliza en las siguientes peticiones al
    mismo dominio.
    """

    def __init__(self):
        self.session_cookies = {}

    @classmethod
    def from_crawler(cls, crawler):
        """Factory que crea el middleware desde el crawler."""
        middleware = cls()
        crawler.signals.connect(middleware.spider_opened, signal=signals.spider_opened)
        return middleware

    def spider_opened(self, spider):
        """Callback que se dispara al abrir el spider."""
        spider.logger.info('SessionManagementMiddleware initialized')

    def process_response(self, request, response, spider):
        """Guarda las cookies relevantes que vengan en la respuesta."""
        if 'Set-Cookie' in response.headers:
            domain = urlparse(response.url).netloc
            cookies = response.headers.getlist('Set-Cookie')

            if domain not in self.session_cookies:
                self.session_cookies[domain] = []

            # Actualiza las cookies guardadas para este dominio.
            for cookie in cookies:
                # Saca el nombre de la cookie.
                cookie_str = cookie.decode('utf-8') if isinstance(cookie, bytes) else cookie
                cookie_name = cookie_str.split('=')[0]

                # Si ya teníamos esa cookie, la sobrescribe.
                self.session_cookies[domain] = [
                    c for c in self.session_cookies[domain]
                    if not c.startswith(cookie_name + '=')
                ]
                self.session_cookies[domain].append(cookie_str)

            spider.logger.debug(f"Saved {len(cookies)} cookies for {domain}")

        return response

    def process_request(self, request, spider):
        """Mete las cookies guardadas en la petición."""
        domain = urlparse(request.url).netloc

        if domain in self.session_cookies and self.session_cookies[domain]:
            # Junta todas las cookies en una única cabecera.
            cookie_header = '; '.join([
                c.split(';')[0] for c in self.session_cookies[domain]
            ])
            request.headers['Cookie'] = cookie_header
            spider.logger.debug(f"Applied cookies to {domain}")


class ProxyRotationMiddleware:
    """
    Va alternando entre varios proxies para esquivar bloqueos por IP.

    NOTA: hay que configurar antes proxies válidos en settings.py.
    Para investigación académica, lo razonable es usar proxies
    institucionales o pedir al sitio un acceso especial.
    """

    def __init__(self, proxies):
        self.proxies = proxies or []
        self.current_proxy_index = 0

    @classmethod
    def from_crawler(cls, crawler):
        """Factory que lee la lista de proxies desde los settings."""
        proxies = crawler.settings.getlist('PROXY_LIST', [])
        return cls(proxies)

    def process_request(self, request, spider):
        """Asigna a la petición el siguiente proxy de la lista."""
        if not self.proxies:
            # Si no hay proxies configurados, no hacemos nada.
            return

        # Va pasando por los proxies en orden secuencial.
        proxy = self.proxies[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)

        request.meta['proxy'] = proxy
        spider.logger.debug(f"Using proxy: {proxy}")


class SmartRetryMiddleware:
    """
    Retry inteligente con backoff exponencial.

    Reintenta cuando hay errores temporales de red o respuestas de rate
    limiting, dejando cada vez más tiempo entre intentos para no saturar
    al servidor.
    """

    def __init__(self, max_retries=5):
        self.max_retries = max_retries

    @classmethod
    def from_crawler(cls, crawler):
        """Factory que lee la configuración desde los settings."""
        max_retries = crawler.settings.getint('SMART_RETRY_TIMES', 5)
        return cls(max_retries)

    def process_response(self, request, response, spider):
        """Gestiona las respuestas con códigos de error."""
        # Códigos que avisan de rate limiting o de errores temporales.
        retry_codes = [429, 500, 502, 503, 504, 408]

        if response.status in retry_codes:
            retry_count = request.meta.get('retry_count', 0)

            if retry_count < self.max_retries:
                # Calcula la espera con backoff exponencial.
                delay = min(2 ** retry_count, 60)  # Tope de 60 segundos

                spider.logger.warning(
                    f"Retrying {request.url} (attempt {retry_count + 1}/{self.max_retries}) "
                    f"after {delay}s due to status {response.status}"
                )

                time.sleep(delay)

                # Genera una nueva petición con el contador subido en uno.
                new_request = request.copy()
                new_request.meta['retry_count'] = retry_count + 1
                new_request.dont_filter = True

                return new_request
            else:
                spider.logger.error(
                    f"Gave up retrying {request.url} after {self.max_retries} attempts"
                )

        return response

    def process_exception(self, request, exception, spider):
        """Gestiona las excepciones de red."""
        retry_count = request.meta.get('retry_count', 0)

        # Excepciones que vale la pena reintentar.
        retryable_exceptions = (
            TimeoutError,
            ConnectionError,
            ConnectionRefusedError,
            ConnectionResetError,
        )

        if isinstance(exception, retryable_exceptions) and retry_count < self.max_retries:
            delay = min(2 ** retry_count, 60)

            spider.logger.warning(
                f"Retrying {request.url} (attempt {retry_count + 1}/{self.max_retries}) "
                f"after {delay}s due to {exception.__class__.__name__}"
            )

            time.sleep(delay)

            new_request = request.copy()
            new_request.meta['retry_count'] = retry_count + 1
            new_request.dont_filter = True

            return new_request
