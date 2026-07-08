# Build stage
FROM golang:1.26 AS builder

WORKDIR /app

COPY . .

RUN GOFIPS140=v1.0.0 go build -tags=no_openssl -buildvcs=false -o rhtas_console ./cmd/rhtas_console

# Final stage
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.8-1782797275

# Set a writable working directory
WORKDIR /tmp
ENV HOME=/tmp

COPY --from=builder /app/rhtas_console /tmp/rhtas_console

USER 65532:65532

# Expose API port
EXPOSE 8080

#ENTRYPOINT
ENTRYPOINT ["/tmp/rhtas_console"]
