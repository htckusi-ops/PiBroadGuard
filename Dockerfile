FROM python:3.11-slim

RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# setcap for nmap raw sockets
RUN apt-get update && apt-get install -y libcap2-bin && rm -rf /var/lib/apt/lists/* && \
    setcap cap_net_raw+ep /usr/bin/nmap

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directories
RUN mkdir -p /app/data/backups /app/data/logs

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
