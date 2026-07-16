BINARY_NAME=rhtas_console
CMD_DIR=cmd/rhtas_console
BUILD_DIR=bin

TUF_PUBLIC_INSTANCE = https://tuf-repo-cdn.sigstore.dev
OAPI_CODEGEN_VERSION := v2.5.1

.PHONY: all
all: generate-openapi build

# Generate Go code from OpenAPI specification using oapi-codegen
.PHONY: generate-openapi
generate-openapi:
	@echo "Generating Go code from OpenAPI specification..."
	oapi-codegen -generate types,chi-server -package models internal/api/openapi/rhtas-console.yaml > internal/models/models.go

.PHONY: build
build: generate-openapi deps
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -tags=no_openssl -v -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

.PHONY: run
run: build
	@echo "Running $(BINARY_NAME)..."
	"./$(BUILD_DIR)/$(BINARY_NAME)" \
		--tuf-repo-url="$(TUF_PUBLIC_INSTANCE)"

.PHONY: deps
deps:
	@echo "Installing dependencies..."
	@go mod tidy
	@go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION)

.PHONY: test
test:
	@echo "Running tests..."
	go test ./...

.PHONY: coverage
coverage:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
