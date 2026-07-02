# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend package and the static frontend.
COPY backend/ ./
COPY frontend/ ../frontend/

EXPOSE 9000

# The frontend is mounted relative to the repo root (../frontend from app/).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000"]
