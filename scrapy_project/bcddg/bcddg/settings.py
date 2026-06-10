# Settings de Scrapy para el proyecto bcddg.
#
# Para simplificar, este fichero solo contiene los ajustes que se usan
# habitualmente. El resto se puede consultar en la documentación oficial:
#
# https://docs.scrapy.org/en/latest/topics/settings.html
# https://docs.scrapy.org/en/latest/topics/downloader-middleware.html
# https://docs.scrapy.org/en/latest/topics/spider-middleware.html

BOT_NAME = "bcddg"

SPIDER_MODULES = ["bcddg.spiders"]
NEWSPIDER_MODULE = "bcddg.spiders"

ADDONS = {}


# =============================================================================
# CONFIGURACIÓN ANTI-SCRAPING REFORZADA
# =============================================================================
# Esta configuración combina varias técnicas para evitar que detecten al
# bot o lo bloqueen. Pensada para investigación académica en ciberseguridad.

# Respeta robots.txt (solo poner en False con permiso expreso del sitio).
ROBOTSTXT_OBEY = True

# Ajustes de concurrencia (bajos para no saturar al servidor).
CONCURRENT_REQUESTS = 2
CONCURRENT_REQUESTS_PER_DOMAIN = 1
# Nota: DOWNLOAD_DELAY está desactivado: usamos HumanLikeDelayMiddleware en su lugar.

# Activa las cookies (las necesita el gestor de sesión).
COOKIES_ENABLED = True
COOKIES_DEBUG = False  # Poner en True para depurar problemas con cookies.

# Timeout de descarga (subido para conexiones lentas).
DOWNLOAD_TIMEOUT = 60

# =============================================================================
# MIDDLEWARES ANTI-BOT
# =============================================================================
# Los middlewares se ejecutan según su prioridad (número más bajo = más prioridad).

DOWNLOADER_MIDDLEWARES = {
    # Middlewares por defecto de Scrapy.
    'scrapy.downloadermiddlewares.httpproxy.HttpProxyMiddleware': 110,

    # Nuestros middlewares anti-bot.
    'bcddg.middlewares_enhanced.ProxyRotationMiddleware': 120,  # Opcional: solo si se usan proxies.
    'bcddg.middlewares_enhanced.HumanLikeDelayMiddleware': 350,
    'bcddg.middlewares_enhanced.RotateUserAgentMiddleware': 400,
    'bcddg.middlewares_enhanced.RefererMiddleware': 500,
    'bcddg.middlewares_enhanced.SessionManagementMiddleware': 600,

    # Middleware de retry mejorado.
    'bcddg.middlewares_enhanced.SmartRetryMiddleware': 550,

    # Desactiva el retry por defecto (lo cubre SmartRetryMiddleware).
    'scrapy.downloadermiddlewares.retry.RetryMiddleware': None,

    # Desactiva el user-agent por defecto (lo cubre RotateUserAgentMiddleware).
    'scrapy.downloadermiddlewares.useragent.UserAgentMiddleware': None,
}

# =============================================================================
# CONFIGURACIÓN DE PROXIES (opcional)
# =============================================================================
# Descomenta y rellena si te están bloqueando por IP.
# Para investigación académica, opciones razonables:
# - Proxies institucionales de la universidad.
# - Proveedores de proxies con uso ético.
# - Pedir acceso por API directamente al sitio.

# PROXY_LIST = [
# 'http://proxy1.example.com:8080',
# 'http://proxy2.example.com:8080',
# ]

# O un servicio de proxy con autenticación:
# PROXY_LIST = [
# 'http://user:pass@proxy.service.com:8080',
# ]

# =============================================================================
# CONFIGURACIÓN DE RETRY
# =============================================================================

RETRY_ENABLED = True
RETRY_TIMES = 8  # Número máximo de reintentos.
RETRY_HTTP_CODES = [500, 502, 503, 504, 408, 429, 403]  # Códigos que disparan reintento.
SMART_RETRY_TIMES = 8  # Lo lee SmartRetryMiddleware.

# =============================================================================
# EXTENSIÓN AUTOTHROTTLE (throttling adaptativo)
# =============================================================================
# AutoThrottle va ajustando los tiempos de descarga según cuánto tarde el servidor.

AUTOTHROTTLE_ENABLED = True
AUTOTHROTTLE_START_DELAY = 3.0  # Espera inicial (conservadora).
AUTOTHROTTLE_MAX_DELAY = 60.0  # Tope si el servidor va lento.
AUTOTHROTTLE_TARGET_CONCURRENCY = 0.5  # Muy conservador (0.5 peticiones en paralelo).
AUTOTHROTTLE_DEBUG = False  # Poner en True para ver las estadísticas de throttling.

# =============================================================================
# CONFIGURACIÓN DE PLAYWRIGHT
# =============================================================================
# Playwright lo usa el spider bc_playwright_ransomware para renderizar JavaScript.
# Esta configuración se aplica de forma global pero cada spider la puede sobrescribir.

DOWNLOAD_HANDLERS = {
    "http": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
    "https": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
}

# Reactor de Twisted (lo necesita Playwright).
TWISTED_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"

# Tipo de navegador que arranca Playwright.
PLAYWRIGHT_BROWSER_TYPE = 'chromium'

# Opciones con las que se lanza el navegador.
PLAYWRIGHT_LAUNCH_OPTIONS = {
    'headless': True,  # Sin interfaz gráfica.
    'args': [
        '--disable-blink-features=AutomationControlled',  # Disimula que es un navegador automatizado.
        '--disable-dev-shm-usage',
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-web-security',  # Puede ayudar con algunas defensas anti-bot.
    ],
}

# Timeout por defecto para la navegación con Playwright.
PLAYWRIGHT_DEFAULT_NAVIGATION_TIMEOUT = 30000  # 30 segundos

# =============================================================================
# CONFIGURACIÓN DE LOGGING
# =============================================================================

LOG_LEVEL = 'INFO'  # Valores: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT = '%(asctime)s [%(name)s] %(levelname)s: %(message)s'
LOG_DATEFORMAT = '%Y-%m-%d %H:%M:%S'

# Descomenta para guardar los logs a fichero.
# LOG_FILE = 'scrapy_run.log'

# =============================================================================
# ITEM PIPELINES (sin uso)
# =============================================================================
# Los spiders devuelven dicts tal cual, así que no usamos Items ni Pipelines de Scrapy.
# Los ficheros pipelines.py / items.py / middlewares.py (boilerplate de Scrapy)
# se quitaron en la limpieza del 19-05-2026: el único middleware activo es
# middlewares_enhanced.py. Si más adelante hace falta un pipeline, hay que crear
# el módulo y descomentar la configuración.

# =============================================================================
# CACHÉ HTTP (útil para desarrollo y depuración)
# =============================================================================
# Activa la caché HTTP (por defecto está apagada).
# Descomentar en desarrollo para no volver a descargar las mismas páginas.

#HTTPCACHE_ENABLED = True
#HTTPCACHE_EXPIRATION_SECS = 86400 # 24 horas
#HTTPCACHE_DIR = "httpcache"
#HTTPCACHE_IGNORE_HTTP_CODES = [403, 404, 500, 503]
#HTTPCACHE_STORAGE = "scrapy.extensions.httpcache.FilesystemCacheStorage"

# =============================================================================
# OTROS AJUSTES
# =============================================================================

# Fija el valor de los settings cuyo default está deprecado.
FEED_EXPORT_ENCODING = "utf-8"

# Desactiva la consola Telnet (por seguridad).
TELNETCONSOLE_ENABLED = False

# =============================================================================
# AVISO DE USO ACADÉMICO
# =============================================================================
# Esta configuración está pensada para investigación académica en ciberseguridad.
# Las medidas anti-scraping están aquí para:
# - No saturar a los servidores objetivo.
# - Respetar los rate limits y robots.txt.
# - Permitir investigación legítima sobre amenazas ransomware.
# - Contribuir a la seguridad pública a través de threat intelligence.
#
# Si vas a usar esto con fines comerciales, revisa y ajusta los settings
# en consecuencia y plantéate pedir permiso expreso al sitio web objetivo.
# =============================================================================
