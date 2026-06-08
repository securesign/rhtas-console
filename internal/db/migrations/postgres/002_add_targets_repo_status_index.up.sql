-- Index to optimize lookups by repo_url and status
CREATE INDEX IF NOT EXISTS idx_targets_repo_status
ON targets (repo_url, status);
