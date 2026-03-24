FROM python:3.11-slim

WORKDIR /app

COPY riskstream/services/normalization/threat-signal/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY riskstream/shared /app/riskstream/shared
COPY riskstream/services/normalization/threat-signal/schemas /app/riskstream/services/normalization/threat-signal/schemas
COPY riskstream/services/normalization/threat-signal/src /app/riskstream/services/normalization/threat-signal/src

ENV PYTHONPATH=/app

CMD ["python", "riskstream/services/normalization/threat-signal/src/main.py"]
