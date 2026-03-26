FROM python:3.11-slim

# nmap + capabilities + WeasyPrint system libs (pango/harfbuzz for HTML→PDF)
RUN apt-get update && apt-get install -y \
    nmap \
    libcap2-bin \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    fontconfig \
    fonts-liberation \
    shared-mime-info \
    && setcap cap_net_raw+ep /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create data directories
RUN mkdir -p /app/data/backups /app/data/logs

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
