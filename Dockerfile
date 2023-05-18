FROM rust:slim-buster

RUN apt-get update && apt-get install --no-install-recommends -y curl perl make && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/omnisette-server/

COPY . .

RUN  cargo build --release

ENTRYPOINT [ "./docker-entrypoint.sh" ]