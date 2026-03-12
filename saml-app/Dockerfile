FROM python:3.11-slim

# python3-saml needs xmlsec1 and its dev headers
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config gcc libxml2-dev libxmlsec1-dev libxmlsec1-openssl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 9400
CMD ["python", "app.py"]
