-- Index to optimize lookups by repo_url and status
CREATE INDEX idx_targets_repo_status
ON targets (repo_url, status);
