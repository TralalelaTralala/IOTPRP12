FROM python:3.11-slim
# tinydtls (DTLSSocket) збирається з вихідних кодів
RUN apt-get update && apt-get install -y --no-install-recommends gcc autoconf automake libtool pkg-config autoconf-archive make libc6-dev git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --retries 10 --timeout 60 -r requirements.txt
COPY ocf_device.py .
EXPOSE 5683/udp 5684/udp
CMD ["python", "-u", "ocf_device.py"]
