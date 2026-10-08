FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Production: NO --reload. Worker count is env-driven (WORKERS, default 1) so a
# big box can run several (they share the Redis cache) without a code change.
# `exec` so uvicorn is PID 1 and receives SIGTERM for a clean shutdown.
CMD ["/bin/sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port 8000 --workers ${WORKERS:-1}"]
