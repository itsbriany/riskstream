FROM python:3.11-slim

WORKDIR /app

COPY riskstream/services/ingestion/cisa-kev/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY riskstream/shared /app/riskstream/shared
COPY riskstream/services/ingestion/cisa-kev/src /app/riskstream/services/ingestion/cisa-kev/src

ENV PORT=8082
ENV ENVIRONMENT=production
ENV PYTHONPATH=/app

EXPOSE 8082

CMD ["python", "riskstream/services/ingestion/cisa-kev/src/main.py"]
