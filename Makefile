# Makefile for User Service

.PHONY: help build run clean test proto docker-build docker-run

# Default target
help:
	@echo "Available targets:"
	@echo "  build             - Build the application"
	@echo "  run               - Run the application"
	@echo "  clean             - Clean build artifacts"
	@echo "  test              - Run all tests"
	@echo "  test-unit         - Run unit tests only"
	@echo "  test-oauth        - Run OAuth integration tests"
	@echo "  test-auth         - Run auth handler tests with coverage"
	@echo "  test-integration  - Run full integration tests (requires DB/Redis)"
	@echo "  test-race         - Run tests with race detection"
	@echo "  proto             - Generate protobuf files"
	@echo "  docker-build      - Build docker image"
	@echo "  docker-run        - Run docker container"

# Build the application
build:
	go build -o bin/user-service cmd/main.go

# Run the application
run:
	go run cmd/main.go

# Clean build artifacts
clean:
	rm -rf bin/

# Run tests
test:
	go test -v ./...

# Run unit tests only
test-unit:
	go test -v ./internal/handler -run "TestAuthHandler_.*_Validation|TestOAuthFlowValidation"

# Run OAuth integration tests
test-oauth:
	go test -v ./internal/handler -run "TestOAuth.*"

# Run auth handler tests with coverage
test-auth:
	go test -v -cover ./internal/handler

# Run integration tests (requires database and Redis)
test-integration:
	@echo "Running OAuth integration tests..."
	@echo "Ensure PostgreSQL and Redis are running before running this target"
	go test -v ./internal/handler -run "TestOAuthLoginIntegration" -timeout 30s

# Run all tests with race detection
test-race:
	go test -v -race ./internal/handler

# Generate protobuf files
proto:
	buf dep update
	buf generate

# Build docker image
docker-build:
	docker build -t user-service:latest .

# Run docker container
docker-run:
	docker run -p 50051:50051 user-service:latest

# Format code
fmt:
	gofumpt -w .
	golines -w .

# Lint code
lint:
	golangci-lint run

# Tidy dependencies
tidy:
	go mod tidy