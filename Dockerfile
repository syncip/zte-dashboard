FROM python:3.12-slim
# iputils-ping: für die ICMP-Pings (ohne fällt das Skript auf TCP-Pings zurück)
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
ENV PYTHONUNBUFFERED=1 ZTE_DB=/data/zte.db ZTE_PORT=8080 TZ=Europe/Berlin
WORKDIR /app
COPY zte_dash.py .
COPY static ./static
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
CMD ["python", "zte_dash.py"]
