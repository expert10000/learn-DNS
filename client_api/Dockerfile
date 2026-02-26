FROM python:3.12-alpine

RUN apk add --no-cache bind-tools ca-certificates

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY api /app/api

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host=0.0.0.0", "--port=8000"]
