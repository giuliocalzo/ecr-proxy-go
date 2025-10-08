FROM golang:1.22-alpine AS builder
WORKDIR /app
# Copy and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

RUN CGO_ENABLED=0 \
    GOOS=linux \
    go build \
    -ldflags="-w -s" \
    -o /app/ecr-proxy


FROM gcr.io/distroless/static-debian12:nonroot

# Run as non-root user
USER nonroot:nonroot

WORKDIR /app

# Copy the binary and certificates from builder
COPY --from=builder --chown=nonroot:nonroot /app/ecr-proxy .

# Environment variables with defaults
ENV AWS_REGION=us-east-1
ENV AWS_ACCOUNT_ID=""
ENV PROXY_PORT=5000

# Expose HTTPS port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/ecr-proxy", "health"] || exit 1

ARG gitsha
ARG version="latest"
LABEL org.opencontainers.image.revision="${gitsha}"
LABEL org.opencontainers.image.version="${version}"
LABEL org.opencontainers.image.description="ECR Proxy for AWS ECR"
LABEL org.opencontainers.image.url="github.com/giuliocalzolari/ecr-proxy"
LABEL org.opencontainers.image.source="https://github.com/giuliocalzolari/ecr-proxy"
LABEL org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["/app/ecr-proxy"]