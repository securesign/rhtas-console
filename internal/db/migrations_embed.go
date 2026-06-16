package db

import "embed"

//go:embed migrations/mysql/*.sql migrations/postgres/*.sql
var MigrationsFS embed.FS
