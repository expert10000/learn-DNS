FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends dnsperf ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /work
CMD ["sh", "-lc", "sleep infinity"]
