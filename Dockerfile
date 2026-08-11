FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY guardbench ./guardbench
COPY LICENSE ./
RUN python -m pip install --no-cache-dir --upgrade 'pip>=26.1.2' 'setuptools>=83' wheel \
    && python -m pip install --no-cache-dir . \
    && python -m pip uninstall -y pip setuptools wheel \
    && python -c "import importlib.util; assert importlib.util.find_spec('pip') is None" \
    && useradd --system --uid 10001 guardbench \
    && mkdir -p /app/artifacts/runs \
    && chown -R guardbench /app/artifacts
USER 10001
EXPOSE 8080
CMD ["uvicorn", "guardbench.api:app", "--host", "0.0.0.0", "--port", "8080"]
