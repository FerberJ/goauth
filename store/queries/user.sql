-- name: GetUser :one
SELECT * FROM auth_users
WHERE id = ? LIMIT 1;

-- name: GetFromMail :one
SELECT * FROM auth_users
WHERE mail = ? LIMIT 1;

-- name: CreateUser :one
INSERT INTO auth_users (
  id, username, firstname, lastname, password_hash, mail, credentials, verified
) VALUES (
  ?, ?, ?, ?, ?, ?, ?, FALSE
)
RETURNING *;

-- name: VerifyUser :exec
UPDATE auth_users
SET
  verified = ?
WHERE id = ?;

-- name: UpdateUser :exec
UPDATE auth_users
SET
  username = ?,
  firstname = ?, 
  lastname = ?, 
  mail = ?
WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM auth_users
WHERE id = ?;

-- name: UserIDExists :one
SELECT EXISTS(
    SELECT 1 FROM auth_users WHERE id = ?
) AS id_exists;

-- name: UserUpdatePassword :exec
UPDATE auth_users
SET
  password_hash = ?
WHERE id = ?;

-- name: UserUpdateSignupCredentials :exec
UPDATE auth_users
SET
  credentials = ?,
  mail = ?
WHERE id = ?;

-- name: GetUsers :many
SELECT * FROM auth_users
ORDER BY id
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');

-- name: CountUsers :one
SELECT COUNT(*) FROM auth_users
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset');