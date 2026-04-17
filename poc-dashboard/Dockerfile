FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --retries 5 --timeout 60 -r requirements.txt

# App code is mounted at runtime via hostPath volume
CMD ["python3", "/app/app.py"]
