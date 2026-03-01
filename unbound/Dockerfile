FROM mvance/unbound:1.20.0

USER root
RUN apt-get update \
  && apt-get install -y --no-install-recommends tcpdump \
  && rm -rf /var/lib/apt/lists/*
