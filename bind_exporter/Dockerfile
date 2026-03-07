FROM python:3.12-alpine

RUN apk add --no-cache bind bind-tools ca-certificates

WORKDIR /app
COPY exporter.py /app/exporter.py

EXPOSE 9119

ENV PORT=9119

CMD ["python", "/app/exporter.py"]