FROM debian:stable-slim

RUN apt-get update && apt-get install -y curl unzip build-essential gdc dub && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY . /opt/omnisette-server/

WORKDIR /opt/omnisette-server/

ENTRYPOINT [ "./docker-entrypoint.sh" ]