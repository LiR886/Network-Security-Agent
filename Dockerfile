FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd -m -u 10001 appuser

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src /app/src
COPY config.yaml /app/config.yaml
COPY data /app/data

RUN chown -R appuser:appuser /app
USER appuser

ENV NSA_CONFIG=/app/config.yaml

# default command is overridden by docker-compose service commands
CMD ["python", "-c", "print('image ready')"]






