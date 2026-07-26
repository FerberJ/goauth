-- +goose Up
CREATE TABLE auth_users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    mail TEXT NOT NULL UNIQUE,
    verified BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE auth_verification (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE auth_refresh (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE auth_password_forgot (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY,          
    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    data TEXT NOT NULL,  
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);

-- +goose Down
DROP TABLE IF EXISTS webauthn_credentials;

DROP TABLE IF EXISTS auth_users;

DROP TABLE IF EXISTS auth_verification;

DROP TABLE IF EXISTS auth_refresh;

DROP TABLE IF EXISTS auth_password_forgot;
