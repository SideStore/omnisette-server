FROM rust:slim-buster

RUN apt-get update && apt-get install --no-install-recommends -y unzip curl perl make && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/omnisette-server/

COPY . .

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

RUN cargo build --release

ENTRYPOINT [ "./docker-entrypoint.sh" ]
