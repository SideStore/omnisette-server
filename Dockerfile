FROM rust:slim-buster AS builder

RUN apt-get update && apt-get install --no-install-recommends -y perl make && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/omnisette-server/

COPY Cargo.* ./

COPY src ./src

ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

RUN cargo build --release


#FROM alpine:3.18 AS runtime
FROM debian:stable-slim AS runtime

#RUN apk add unzip curl
RUN apt-get update && apt-get install --no-install-recommends -y unzip curl ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/omnisette-server/

COPY docker-entrypoint.sh ./

COPY --from=builder /opt/omnisette-server/target/release/omnisette-server ./

ENTRYPOINT [ "./docker-entrypoint.sh" ]
