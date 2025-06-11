BINARY_NAME=rhtas_console
CMD_DIR=cmd/rhtas_console
BUILD_DIR=bin

.PHONY: all
all: generate-openapi build

# Generate Go code from OpenAPI specification using oapi-codegen
.PHONY: generate-openapi
generate-openapi: deps
	@echo "Generating Go code from OpenAPI specification..."
	oapi-codegen -generate types,chi-server -package models internal/api/openapi/rhtas-console.yaml > internal/models/models.go

.PHONY: build
build: generate-openapi
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -v -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

.PHONY: run
run: build
	@echo "Running $(BINARY_NAME)..."
	@./$(BUILD_DIR)/$(BINARY_NAME)

.PHONY: clean
clean:
	@echo "Cleaning build artifacts and generated files..."
	@rm -rf $(BUILD_DIR)
	@rm -f internal/models/models.go

.PHONY: deps
deps:
	@echo "Installing dependencies..."
	@go mod tidy
	@go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest
