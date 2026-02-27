FROM python:3.12-alpine

WORKDIR /app

RUN apk add --no-cache openssl

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY api /app/api
COPY start.sh /start.sh
RUN chmod +x /start.sh

ENV PYTHONUNBUFFERED=1

EXPOSE 443

ENTRYPOINT ["/start.sh"]
