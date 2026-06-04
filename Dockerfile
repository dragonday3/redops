FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
COPY templates/ templates/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["redops"]
CMD ["--help"]
