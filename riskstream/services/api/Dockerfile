FROM python:3.12-slim

WORKDIR /app

RUN python -m pip install --no-cache-dir minio

COPY riskstream/services/api/src /app/riskstream/services/api/src
COPY riskstream/shared /app/riskstream/shared

ENV PYTHONPATH=/app

EXPOSE 8080
CMD ["python", "/app/riskstream/services/api/src/main.py"]
