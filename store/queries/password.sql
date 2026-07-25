-- name: CreatePasswordForgot :one
INSERT INTO auth_password_forgot (
    id, token_id, user_id, issued_at, expires_at, revoked
) VALUES (
    ?, ?, ?, ?, ?, FALSE
)
RETURNING *;

-- name: PasswordForgotExists :one
SELECT EXISTS(
    SELECT 1 FROM auth_password_forgot WHERE token_id = ?
) AS token_exists;

-- name: PasswordForgotIDExists :one
SELECT EXISTS(
    SELECT 1 FROM auth_password_forgot WHERE id = ?
) AS id_exists;

-- name: GetPasswordForgot :one
SELECT * FROM auth_password_forgot
WHERE token_id = ? LIMIT 1;

-- name: PasswordForgotRevoke :exec
UPDATE auth_password_forgot
SET
    revoked = TRUE
WHERE id = ?;