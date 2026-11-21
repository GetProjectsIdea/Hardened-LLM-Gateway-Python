FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 gateway && mkdir -p /data && chown gateway /data
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY llm_gateway ./llm_gateway
RUN pip install --no-cache-dir ".[web]"
USER gateway
EXPOSE 8088
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8088/healthz',timeout=3)"
# Production: use a WSGI server, e.g. pip install gunicorn and run gunicorn "llm_gateway.wsgi:app"
CMD ["python", "-m", "llm_gateway", "serve"]
