FROM golang:1.25-alpine AS builder
WORKDIR /app
# Copy and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

RUN CGO_ENABLED=0 \
    GOOS=linux \
    go build  \
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
ENV AWS_ACCOUNT_ID=
ENV PROXY_PORT=5000

# Expose HTTPS port
EXPOSE ${PROXY_PORT}

ARG gitsha
LABEL org.opencontainers.image.revision="${gitsha}"
LABEL org.opencontainers.image.description="ECR Proxy for AWS ECR"
LABEL org.opencontainers.image.url="github.com/giuliocalzolari/ecr-proxy"
ENTRYPOINT ["/app/ecr-proxy"]
