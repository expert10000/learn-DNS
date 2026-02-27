FROM python:3.12-alpine

WORKDIR /app

RUN apk add --no-cache openssl

COPY api /app/api
COPY start.sh /start.sh
RUN chmod +x /start.sh

ENV PYTHONUNBUFFERED=1

EXPOSE 853

ENTRYPOINT ["/start.sh"]
