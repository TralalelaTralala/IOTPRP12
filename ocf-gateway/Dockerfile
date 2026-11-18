FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends gcc autoconf automake libtool pkg-config autoconf-archive make libc6-dev git curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --retries 10 --timeout 60 -r requirements.txt
COPY ocf_gateway.py ui.html ./
EXPOSE 8090
CMD ["python", "-u", "ocf_gateway.py"]
