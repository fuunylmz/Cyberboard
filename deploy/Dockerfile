FROM rust:1.85-bookworm AS builder

ARG APP
WORKDIR /workspace
COPY . .
RUN test -n "$APP" && cargo build --locked --release -p "$APP"

FROM debian:bookworm-slim

ARG APP
RUN useradd --system --create-home --uid 10001 cyberboard
COPY --from=builder /workspace/target/release/${APP} /usr/local/bin/cyberboard
USER cyberboard
ENTRYPOINT ["/usr/local/bin/cyberboard"]
