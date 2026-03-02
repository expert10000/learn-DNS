FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends swaks ca-certificates \
  && rm -rf /var/lib/apt/lists/*

CMD ["sh", "-lc", "sleep infinity"]
