FROM python:3.12-alpine

RUN apk add --no-cache unbound ca-certificates

WORKDIR /app
COPY exporter.py /app/exporter.py

EXPOSE 9167

ENV PORT=9167

CMD ["python", "/app/exporter.py"]