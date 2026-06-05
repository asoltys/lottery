# Build + run the lottery engine (forked Cube engine + arcade web server).
# The browser client (index.html + bundle.js) is embedded into the binary via
# include_str!, so the runtime image is self-contained.

FROM rust:1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cd server && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/server/target/release/lottery-engine /usr/local/bin/lottery-engine
WORKDIR /data
ENTRYPOINT ["lottery-engine"]
