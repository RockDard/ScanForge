FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV QA_PORTAL_HOST=0.0.0.0
ENV QA_PORTAL_PORT=8000
ENV QA_PORTAL_RELOAD=0
ENV QA_PORTAL_DATA_DIR=/app/data
ENV PATH=/opt/venv/bin:$PATH

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    ca-certificates \
    build-essential \
    cmake \
    ninja-build \
    clang \
    clang-tidy \
    cppcheck \
    valgrind \
    afl++ \
    qt6-base-dev \
    qt6-base-dev-tools \
    qt6-declarative-dev \
    qt6-tools-dev \
    qt6-tools-dev-tools \
    qmake6 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN python3 -m venv /opt/venv && pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

RUN chmod +x /app/run-server.sh /app/run-worker.sh /app/run-sync-kb.sh /app/run-tests.sh

RUN useradd --create-home --shell /bin/bash portal && \
    mkdir -p /app/data && \
    chown -R portal:portal /app /opt/venv

USER portal

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"

CMD ["./run-server.sh"]
