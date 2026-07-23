-- name: CreateVerification :one
INSERT INTO auth_verification (
    id, token_id, user_id, issued_at, expires_at, revoked
) VALUES (
    ?, ?, ?, ?, ?, FALSE
)
RETURNING *;

-- name: VerificationExists :one
SELECT EXISTS(
    SELECT 1 FROM auth_verification WHERE token_id = ?
) AS token_exists;

-- name: VerificationIDExists :one
SELECT EXISTS(
    SELECT 1 FROM auth_verification WHERE id = ?
) AS id_exists;

-- name: GetVerification :one
SELECT * FROM auth_verification
WHERE token_id = ? LIMIT 1;

-- name: VerificationRevoke :exec
UPDATE auth_verification
SET
    revoked = TRUE
WHERE id = ?;