FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code is mounted at runtime via hostPath volume
CMD ["python3", "/app/app.py"]
