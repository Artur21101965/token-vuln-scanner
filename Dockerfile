FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git tor procps && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt 'httpx[socks]'

COPY . .

RUN mkdir -p logs

EXPOSE 8000

CMD ["python", "run_dashboard.py"]
