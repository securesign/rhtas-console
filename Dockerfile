# Build stage
FROM golang:1.25 AS builder

WORKDIR /app

COPY . .

RUN go build -buildvcs=false -o rhtas_console ./cmd/rhtas_console

# Final stage
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.7-1769056855

# Set a writable working directory
WORKDIR /tmp
ENV HOME=/tmp

COPY --from=builder /app/rhtas_console /tmp/rhtas_console
COPY internal/db/migrations /tmp/internal/db/migrations

USER 65532:65532

# Expose API port
EXPOSE 8080

#ENTRYPOINT
ENTRYPOINT ["/tmp/rhtas_console"]
