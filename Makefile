BINARY_NAME=rhtas_console
CMD_DIR=cmd/rhtas_console
BUILD_DIR=bin

# Database config
DB_NAME = tuf_trust
DB_USER = rootuser
DB_PASS = root
DB_ROOT_PASS = rootpassword
DB_PORT = 3306
DB_CONTAINER = mariadb
DB_IMAGE = registry.redhat.io/rhel9/mariadb-105@sha256:050dd5a7a32395b73b8680570e967e55050b152727412fdd73a25d8816e62d53
DB_DSN = $(DB_USER):$(DB_PASS)@tcp(localhost:$(DB_PORT))/$(DB_NAME)
TUF_PUBLIC_INSTANCE = https://tuf-repo-cdn.sigstore.dev

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
	go build -v -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

.PHONY: run
run: build deploy-mariadb
	@echo "Waiting for MariaDB to be ready..."
	@until podman exec $(DB_CONTAINER) mysqladmin ping -h "127.0.0.1" -u$(DB_USER) -p$(DB_PASS) --silent; do \
		echo "Waiting for database..."; \
		sleep 1; \
	done
	@echo "MariaDB is up."
	@echo "Running $(BINARY_NAME)..."
	@DB_DSN="$(DB_DSN)" \
	TUF_REPO_URL="$(TUF_PUBLIC_INSTANCE)" \
	"./$(BUILD_DIR)/$(BINARY_NAME)"

.PHONY: deps
deps:
	@echo "Installing dependencies..."
	@go mod tidy
	@go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest

# Database Management
.PHONY: deploy-mariadb
deploy-mariadb:
	@echo "Starting MariaDB container..."
	@if podman ps -a --format '{{.Names}}' | grep -q "^$(DB_CONTAINER)$$"; then \
		echo "Container $(DB_CONTAINER) already exists. Removing..."; \
		podman rm -f $(DB_CONTAINER); \
	fi
	podman run -d --name $(DB_CONTAINER) \
	  -e MYSQL_ROOT_PASSWORD=$(DB_ROOT_PASS) \
	  -e MYSQL_DATABASE=$(DB_NAME) \
	  -e MYSQL_USER=$(DB_USER) \
	  -e MYSQL_PASSWORD=$(DB_PASS) \
	  -p $(DB_PORT):3306 \
	  $(DB_IMAGE)
	@echo "MariaDB started. DSN: $(DB_DSN)"

.PHONY: stop-mariadb
stop-mariadb:
	@echo "Stopping MariaDB container..."
	podman stop $(DB_CONTAINER)

.PHONY: clean-mariadb
clean-mariadb:
	@echo "Removing MariaDB container..."
	podman rm -f $(DB_CONTAINER)

.PHONY: restart-mariadb
restart-mariadb: stop-mariadb deploy-mariadb

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@$(MAKE) clean-mariadb
