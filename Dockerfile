FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLOWTRAGENT_HOST=0.0.0.0 \
    FLOWTRAGENT_PORT=5000 \
    FLOWTRAGENT_PYTHON=python

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        curl \
        graphviz \
        libgomp1 \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-docker.txt .
RUN python -m pip install --upgrade pip \
    && python -m pip install --index-url https://download.pytorch.org/whl/cpu torch==2.3.1 \
    && python -m pip install -r requirements-docker.txt

COPY . .
RUN mkdir -p reports data/pcap data/csv data/index data/rag data/live/incoming \
    && chmod +x scripts/run_web_prod.sh

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${FLOWTRAGENT_PORT}/health" >/dev/null || exit 1

CMD ["bash", "scripts/run_web_prod.sh"]
