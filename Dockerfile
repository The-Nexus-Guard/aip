# AIP Verification Service Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Copy and install requirements
COPY service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY service/ ./service/

WORKDIR /app/service

# Expose port
EXPOSE 8000

# Run the service
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
