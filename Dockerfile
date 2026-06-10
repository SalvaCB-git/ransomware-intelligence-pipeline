FROM python:3.14-slim

# Dependencias del sistema (ARM64 compatible)
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    libxml2-dev \
    libxslt1-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instala dependencias Python (flask y demás ya pinneados en requirements.txt)
COPY scrapy_project/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Instala Playwright + Chromium para ARM64
RUN playwright install chromium --with-deps

# Copia el proyecto Scrapy (sin venv)
COPY scrapy_project/ ./scrapy_project/

# Copia la interfaz web + módulo compartido del juez Gemma 4
COPY app.py .
COPY judge_core.py .

# Directorio de outputs
RUN mkdir -p /app/outputs /app/data

EXPOSE 7000

CMD ["python", "app.py"]
