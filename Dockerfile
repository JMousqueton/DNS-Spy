FROM python:3.12-slim

# Install system dependencies required by Playwright and Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libwayland-client0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    libicu74 \
    libgstreamer-plugins-bad1.0-0 \
    libflite1 \
    libwebpdemux2 \
    libavif16 \
    libharfbuzz-icu0 \
    libmanette-0.2-0 \
    libhyphen0 \
    libwoff1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium browser and all its system dependencies
RUN playwright install-deps chromium && playwright install chromium

COPY . .

# Create screenshots directory
RUN mkdir -p static/screenshots

EXPOSE 5005

ENV PYTHONUNBUFFERED=1

CMD ["python", "run.py"]
