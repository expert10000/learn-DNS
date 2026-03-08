FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir dnspython==2.6.1

COPY traffic_gen.py /app/traffic_gen.py

ENTRYPOINT ["python", "/app/traffic_gen.py"]
