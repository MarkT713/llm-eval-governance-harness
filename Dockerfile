FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY guardbench ./guardbench
COPY web ./web
COPY corpora ./corpora
COPY policies ./policies
COPY examples ./examples
RUN pip install --no-cache-dir . && useradd --system --uid 10001 guardbench && mkdir -p /app/artifacts/runs && chown -R guardbench /app/artifacts
USER 10001
EXPOSE 8080
CMD ["uvicorn", "guardbench.api:app", "--host", "0.0.0.0", "--port", "8080"]
