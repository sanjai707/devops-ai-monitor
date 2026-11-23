FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py monitor.py incident_manager.py database.py thresholds.py ai_investigator.py docker_event_collector.py evaluation.py ./
COPY evaluation ./evaluation
COPY providers ./providers
COPY models ./models
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
