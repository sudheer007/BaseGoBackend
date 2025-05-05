# Variables
BINARY_NAME=gobackend_api
COVERAGE_FILE=coverage.out

# Default target executed when no arguments are given to make.
default: build

## Run
run: ## Run the API locally using go run (loads .env)
	@echo "Starting the application locally..."
	go run cmd/api/main.go

## Build
build: test ## Build the application binary (runs tests first)
	@echo "Building the application binary..."
	go build -o $(BINARY_NAME) cmd/api/main.go
	@echo "Build complete: $(BINARY_NAME)"

## Test
test: ## Run tests
	@echo "Running tests..."
	go test ./... -v

## Test with coverage
test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test ./... -coverprofile=$(COVERAGE_FILE)
	go tool cover -html=$(COVERAGE_FILE)

## Clean
clean: ## Remove previous build artifacts
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)
	rm -f $(COVERAGE_FILE)

## CI Test
ci-test: ## Run tests in CI environment
	@echo "Running tests in CI environment..."
	go test ./... -coverprofile=$(COVERAGE_FILE)
	go tool cover -func=$(COVERAGE_FILE)

## Format
fmt: ## Format code
	@echo "Formatting code..."
	go fmt ./...

## Lint
lint: ## Run linters
	@echo "Running linters..."
	golangci-lint run

## Help
help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: default run build test test-coverage clean ci-test fmt lint help 