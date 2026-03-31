FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create data dirs
RUN mkdir -p reports logs

EXPOSE 5000

ENV FLASK_ENV=production

CMD ["python", "app.py", "--web", "--host", "0.0.0.0", "--port", "5000"]
