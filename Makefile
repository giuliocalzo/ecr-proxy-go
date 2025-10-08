SRC_DIR := .
GO := go
COMMIT_HASH := $(shell git rev-parse HEAD)

.PHONY: all build test fmt vet lint run exec docker-build push helm-docs

# Commands
all: build test

build: fmt
	@echo "Building the binary..."
	$(GO) build -o app $(SRC_DIR)

test:
	@echo "Running tests..."
	$(GO) test ./... -v


fmt:
	@echo "Formatting the code..."
	$(GO) fmt ./...

vet:
	@echo "Vet the code..."
	$(GO) vet ./...

lint:
	@echo "Linting the code..."
	@golint ./...

run:
	@echo "Running the application..."
	$(GO) run main.go

exec:
	@podman build -f Dockerfile -t ecr-proxy:$(COMMIT_HASH) .
	@podman run ecr-proxy:$(COMMIT_HASH)

docker-build:
	@podman build --build-arg gitsha=$(COMMIT_HASH) -f Dockerfile -t ecr-proxy:$(COMMIT_HASH) .
	@podman tag ecr-proxy:$(COMMIT_HASH) ecr-proxy:latest

push: docker-build
	@if [ -z "$(TARGET)" ]; then echo "Error: TARGET variable is not set"; exit 1; fi
	@podman push ecr-proxy:$(COMMIT_HASH) $(TARGET):$(COMMIT_HASH)
	@podman push ecr-proxy:latest $(TARGET):latest

helm-docs:
	@echo "Generating Helm documentation..."
	@helm-docs