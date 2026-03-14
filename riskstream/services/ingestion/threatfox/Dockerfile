FROM python:3.11-slim

WORKDIR /app

COPY riskstream/services/ingestion/threatfox/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY riskstream/shared /app/riskstream/shared
COPY riskstream/services/ingestion/threatfox/src /app/riskstream/services/ingestion/threatfox/src

ENV PORT=8081
ENV ENVIRONMENT=production
ENV PYTHONPATH=/app

EXPOSE 8081

CMD ["python", "riskstream/services/ingestion/threatfox/src/main.py"]
