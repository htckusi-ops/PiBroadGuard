FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nmap \
    libcap2-bin \
    # WeasyPrint system dependencies
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    fonts-liberation \
    && setcap cap_net_raw+ep /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directories
RUN mkdir -p /app/data/backups /app/data/logs

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
