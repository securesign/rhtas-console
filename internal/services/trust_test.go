package services

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	mysqlMigrate "github.com/golang-migrate/migrate/v4/database/mysql"
	postgresMigrate "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

// Test database configuration from environment
var (
	mysqlDSN    = getEnvOrDefault("MYSQL_DSN", "root:testpass@tcp(localhost:3306)/tuf_trust_test?parseTime=true")
	postgresDSN = getEnvOrDefault("POSTGRES_DSN", "postgresql://testuser:testpass@localhost:5432/tuf_trust_test?sslmode=disable")
)

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// setupMySQLTestDB creates a fresh MySQL test database and runs migrations
func setupMySQLTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	// Connect to MySQL server
	db, err := sql.Open("mysql", mysqlDSN)
	if err != nil {
		t.Skipf("MySQL not available: %v", err)
		return nil, nil
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Skipf("MySQL not reachable: %v", err)
		return nil, nil
	}

	// Run migrations
	driver, err := mysqlMigrate.WithInstance(db, &mysqlMigrate.Config{})
	if err != nil {
		_ = db.Close()
		t.Fatalf("Failed to create MySQL migration driver: %v", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://../../internal/db/migrations/mysql",
		"mysql",
		driver,
	)
	if err != nil {
		_ = db.Close()
		t.Fatalf("Failed to create migration instance: %v", err)
	}

	// Force version to -1 to reset migration state
	_ = m.Force(-1)

	// Run migrations
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		_ = db.Close()
		t.Fatalf("Failed to run MySQL migrations: %v", err)
	}

	cleanup := func() {
		// Clean up: drop all tables
		_, _ = db.Exec("DROP TABLE IF EXISTS targets")
		_, _ = db.Exec("DROP TABLE IF EXISTS schema_migrations")
		_ = db.Close()
	}

	return db, cleanup
}

// setupPostgresTestDB creates a fresh PostgreSQL test database and runs migrations
func setupPostgresTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	// Connect to PostgreSQL server
	db, err := sql.Open("postgres", postgresDSN)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
		return nil, nil
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Skipf("PostgreSQL not reachable: %v", err)
		return nil, nil
	}

	// Run migrations
	driver, err := postgresMigrate.WithInstance(db, &postgresMigrate.Config{})
	if err != nil {
		_ = db.Close()
		t.Fatalf("Failed to create PostgreSQL migration driver: %v", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://../../internal/db/migrations/postgres",
		"postgres",
		driver,
	)
	if err != nil {
		_ = db.Close()
		t.Fatalf("Failed to create migration instance: %v", err)
	}

	// Force version to -1 to reset migration state
	_ = m.Force(-1)

	// Run migrations
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		_ = db.Close()
		t.Fatalf("Failed to run PostgreSQL migrations: %v", err)
	}

	cleanup := func() {
		// Clean up: drop all tables
		_, _ = db.Exec("DROP TABLE IF EXISTS targets")
		_, _ = db.Exec("DROP TABLE IF EXISTS schema_migrations")
		_ = db.Close()
	}

	return db, cleanup
}

func TestMySQLConnection(t *testing.T) {
	db, cleanup := setupMySQLTestDB(t)
	if db == nil {
		return // Skipped
	}
	defer cleanup()

	// Verify tables were created
	var tableName string
	err := db.QueryRow("SHOW TABLES LIKE 'targets'").Scan(&tableName)
	if err != nil {
		t.Fatalf("targets table not found: %v", err)
	}
	if tableName != "targets" {
		t.Errorf("expected table 'targets', got %q", tableName)
	}
}

func TestPostgreSQLConnection(t *testing.T) {
	db, cleanup := setupPostgresTestDB(t)
	if db == nil {
		return // Skipped
	}
	defer cleanup()

	// Verify tables were created
	var tableName string
	err := db.QueryRow("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'targets'").Scan(&tableName)
	if err != nil {
		t.Fatalf("targets table not found: %v", err)
	}
	if tableName != "targets" {
		t.Errorf("expected table 'targets', got %q", tableName)
	}
}

func TestMySQLTargetCRUD(t *testing.T) {
	db, cleanup := setupMySQLTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	testTargetCRUD(t, db, "mysql")
}

func TestPostgreSQLTargetCRUD(t *testing.T) {
	db, cleanup := setupPostgresTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	testTargetCRUD(t, db, "postgres")
}

// testTargetCRUD tests Create, Read, Update, Delete operations on targets table
func testTargetCRUD(t *testing.T, db *sql.DB, dbType string) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// Test INSERT
	var insertQuery string
	if dbType == "mysql" {
		insertQuery = `
			INSERT INTO targets (repo_url, target_name, type, status, content, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`
	} else {
		insertQuery = `
			INSERT INTO targets (repo_url, target_name, type, status, content, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`
	}

	result, err := db.ExecContext(ctx, insertQuery,
		"https://tuf.example.com",
		"rekor.pub",
		"rekor",
		"active",
		`{"version": 1}`,
		now,
		now,
	)
	if err != nil {
		t.Fatalf("Failed to insert target: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		t.Fatalf("Failed to get rows affected: %v", err)
	}
	if rowsAffected != 1 {
		t.Errorf("Expected 1 row affected, got %d", rowsAffected)
	}

	// Test SELECT
	var selectQuery string
	if dbType == "mysql" {
		selectQuery = "SELECT id, repo_url, target_name, type, status FROM targets WHERE target_name = ?"
	} else {
		selectQuery = "SELECT id, repo_url, target_name, type, status FROM targets WHERE target_name = $1"
	}

	var id int64
	var repoURL, targetName, targetType, status string
	err = db.QueryRowContext(ctx, selectQuery, "rekor.pub").Scan(&id, &repoURL, &targetName, &targetType, &status)
	if err != nil {
		t.Fatalf("Failed to select target: %v", err)
	}

	if repoURL != "https://tuf.example.com" {
		t.Errorf("Expected repo_url 'https://tuf.example.com', got %q", repoURL)
	}
	if targetName != "rekor.pub" {
		t.Errorf("Expected target_name 'rekor.pub', got %q", targetName)
	}
	if targetType != "rekor" {
		t.Errorf("Expected type 'rekor', got %q", targetType)
	}
	if status != "active" {
		t.Errorf("Expected status 'active', got %q", status)
	}

	// Test UPDATE
	var updateQuery string
	if dbType == "mysql" {
		updateQuery = "UPDATE targets SET status = ?, updated_at = ? WHERE id = ?"
	} else {
		updateQuery = "UPDATE targets SET status = $1, updated_at = $2 WHERE id = $3"
	}

	updatedAt := now.Add(1 * time.Hour)
	result, err = db.ExecContext(ctx, updateQuery, "inactive", updatedAt, id)
	if err != nil {
		t.Fatalf("Failed to update target: %v", err)
	}

	rowsAffected, err = result.RowsAffected()
	if err != nil {
		t.Fatalf("Failed to get rows affected: %v", err)
	}
	if rowsAffected != 1 {
		t.Errorf("Expected 1 row affected by update, got %d", rowsAffected)
	}

	// Verify UPDATE
	err = db.QueryRowContext(ctx, selectQuery, "rekor.pub").Scan(&id, &repoURL, &targetName, &targetType, &status)
	if err != nil {
		t.Fatalf("Failed to select updated target: %v", err)
	}
	if status != "inactive" {
		t.Errorf("Expected updated status 'inactive', got %q", status)
	}

	// Test DELETE
	var deleteQuery string
	if dbType == "mysql" {
		deleteQuery = "DELETE FROM targets WHERE id = ?"
	} else {
		deleteQuery = "DELETE FROM targets WHERE id = $1"
	}

	result, err = db.ExecContext(ctx, deleteQuery, id)
	if err != nil {
		t.Fatalf("Failed to delete target: %v", err)
	}

	rowsAffected, err = result.RowsAffected()
	if err != nil {
		t.Fatalf("Failed to get rows affected: %v", err)
	}
	if rowsAffected != 1 {
		t.Errorf("Expected 1 row affected by delete, got %d", rowsAffected)
	}

	// Verify DELETE
	err = db.QueryRowContext(ctx, selectQuery, "rekor.pub").Scan(&id, &repoURL, &targetName, &targetType, &status)
	if err != sql.ErrNoRows {
		t.Errorf("Expected sql.ErrNoRows after delete, got %v", err)
	}
}

func TestMySQLUniqueConstraint(t *testing.T) {
	db, cleanup := setupMySQLTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	testUniqueConstraint(t, db, "mysql")
}

func TestPostgreSQLUniqueConstraint(t *testing.T) {
	db, cleanup := setupPostgresTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	testUniqueConstraint(t, db, "postgres")
}

func testUniqueConstraint(t *testing.T, db *sql.DB, dbType string) {
	ctx := context.Background()
	now := time.Now().UTC()

	var insertQuery string
	if dbType == "mysql" {
		insertQuery = `
			INSERT INTO targets (repo_url, target_name, type, status, content, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`
	} else {
		insertQuery = `
			INSERT INTO targets (repo_url, target_name, type, status, content, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`
	}

	// Insert first target
	_, err := db.ExecContext(ctx, insertQuery,
		"https://tuf.example.com",
		"fulcio.crt.pem",
		"fulcio",
		"active",
		`{"version": 1}`,
		now,
		now,
	)
	if err != nil {
		t.Fatalf("Failed to insert first target: %v", err)
	}

	// Try to insert duplicate (same repo_url + target_name)
	_, err = db.ExecContext(ctx, insertQuery,
		"https://tuf.example.com",
		"fulcio.crt.pem",
		"fulcio",
		"active",
		`{"version": 2}`,
		now,
		now,
	)
	if err == nil {
		t.Fatal("Expected error inserting duplicate target, got nil")
	}

	// Verify error message contains "Duplicate" or "unique" or "conflict"
	errMsg := strings.ToLower(err.Error())
	if !strings.Contains(errMsg, "duplicate") && !strings.Contains(errMsg, "unique") && !strings.Contains(errMsg, "conflict") {
		t.Errorf("Expected unique constraint error, got: %v", err)
	}
}

func TestMySQLIndex(t *testing.T) {
	db, cleanup := setupMySQLTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	// Check that index exists using information_schema
	var indexName string
	err := db.QueryRow(`
		SELECT INDEX_NAME
		FROM INFORMATION_SCHEMA.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE()
		AND TABLE_NAME = 'targets'
		AND INDEX_NAME = 'idx_targets_repo_status'
		LIMIT 1
	`).Scan(&indexName)
	if err != nil {
		t.Fatalf("Index idx_targets_repo_status not found: %v", err)
	}
	if indexName != "idx_targets_repo_status" {
		t.Errorf("Expected index 'idx_targets_repo_status', got %q", indexName)
	}
}

func TestPostgreSQLIndex(t *testing.T) {
	db, cleanup := setupPostgresTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	// Check that index exists
	var indexName string
	err := db.QueryRow(`
		SELECT indexname
		FROM pg_indexes
		WHERE schemaname = 'public'
		AND indexname = 'idx_targets_repo_status'
	`).Scan(&indexName)
	if err != nil {
		t.Fatalf("Index idx_targets_repo_status not found: %v", err)
	}
	if indexName != "idx_targets_repo_status" {
		t.Errorf("Expected index 'idx_targets_repo_status', got %q", indexName)
	}
}

func TestMySQLTimestampHandling(t *testing.T) {
	db, cleanup := setupMySQLTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// Insert with NOW()
	_, err := db.ExecContext(ctx, `
		INSERT INTO targets (repo_url, target_name, type, status, content, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, NOW(), NOW())
	`, "https://tuf.example.com", "test.target", "test", "active", "{}")
	if err != nil {
		t.Fatalf("Failed to insert with NOW(): %v", err)
	}

	// Verify timestamp was set
	var createdAt time.Time
	err = db.QueryRowContext(ctx, "SELECT created_at FROM targets WHERE target_name = ?", "test.target").Scan(&createdAt)
	if err != nil {
		t.Fatalf("Failed to read created_at: %v", err)
	}

	if createdAt.IsZero() {
		t.Error("Expected non-zero created_at timestamp")
	}
}

func TestPostgreSQLTimestampHandling(t *testing.T) {
	db, cleanup := setupPostgresTestDB(t)
	if db == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// Insert with CURRENT_TIMESTAMP
	_, err := db.ExecContext(ctx, `
		INSERT INTO targets (repo_url, target_name, type, status, content, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, "https://tuf.example.com", "test.target", "test", "active", "{}")
	if err != nil {
		t.Fatalf("Failed to insert with CURRENT_TIMESTAMP: %v", err)
	}

	// Verify timestamp was set
	var createdAt time.Time
	err = db.QueryRowContext(ctx, "SELECT created_at FROM targets WHERE target_name = $1", "test.target").Scan(&createdAt)
	if err != nil {
		t.Fatalf("Failed to read created_at: %v", err)
	}

	if createdAt.IsZero() {
		t.Error("Expected non-zero created_at timestamp")
	}
}
