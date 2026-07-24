-- name: CreateRefresh :one
INSERT INTO auth_refresh (
    id, token_id, user_id, issued_at, expires_at, revoked
) VALUES (
    ?, ?, ?, ?, ?, FALSE
)
RETURNING *;

-- name: RefreshExists :one
SELECT EXISTS(
    SELECT 1 FROM auth_refresh WHERE token_id = ?
) AS token_exists;

-- name: RefreshIDExists :one
SELECT EXISTS(
    SELECT 1 FROM auth_refresh WHERE id = ?
) AS id_exists;

-- name: GetRefresh :one
SELECT * FROM auth_refresh
WHERE token_id = ? LIMIT 1;

-- name: RefreshRevoke :exec
UPDATE auth_refresh
SET
    revoked = TRUE
WHERE id = ?;

-- name: DeleteRefresh :exec
DELETE FROM auth_refresh
WHERE id = ?;