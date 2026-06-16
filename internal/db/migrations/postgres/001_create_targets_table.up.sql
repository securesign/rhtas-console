CREATE TABLE IF NOT EXISTS targets (
    id BIGSERIAL PRIMARY KEY,
    repo_url VARCHAR(255) NOT NULL,
    target_name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    UNIQUE (repo_url, target_name)
);
