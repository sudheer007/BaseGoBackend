# Variables
BINARY_NAME=gobackend_api

# Default target executed when no arguments are given to make.
default: build

## Run
run: ## Run the API locally using go run (loads .env)
	@echo "Starting the application locally..."
	go run cmd/api/main.go

## Build
build: ## Build the application binary
	@echo "Building the application binary..."
	go build -o $(BINARY_NAME) cmd/api/main.go
	@echo "Build complete: $(BINARY_NAME)"

## Test
test: ## Run tests
	@echo "Running tests..."
	go test ./...

## Clean
clean: ## Remove previous build artifacts
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)

## Help
help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: default run build test clean help 